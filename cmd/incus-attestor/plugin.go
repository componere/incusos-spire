package main

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	workloadattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/workloadattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/componere/incusos-spire/internal/attestor"
	"github.com/componere/incusos-spire/internal/incus/identity"
	incusv1alpha1 "github.com/componere/incusos-spire/proto/componere/incus/v1alpha1"
)

// referenceTypeURL is the only google.protobuf.Any type URL this plugin
// attests. It must equal the agent's brokers[].allowed_reference_types[]
// type_url exactly; any other type URL is InvalidArgument, which is how a
// reference-capable attestor declines a reference it does not own.
const referenceTypeURL = "type.googleapis.com/componere.incus.v1alpha1.IncusInstanceReference"

// This compile-time assertion keeps the plugin wired to SPIRE's logger.
var _ pluginsdk.NeedsLogger = (*Plugin)(nil)

// deriver is the port into the pure attestation core. The plugin owns no trust
// rules of its own; it only translates protobuf into a core call and the core
// answer into a gRPC answer.
type deriver interface {
	// Derive returns the frozen selector set for ref or a core sentinel error.
	Derive(ctx context.Context, ref attestor.Reference) ([]attestor.Selector, error)
}

// Config is the agent's plugin_data block for WorkloadAttestor "incus". Every
// field maps onto [identity.Config]; all are required except that exactly one
// of ServerCertPath and ServerCertFingerprint must pin the Incus server.
type Config struct {
	// ServerURL is the Incus HTTPS origin, for example https://incus.example:8443.
	ServerURL string `hcl:"server_url"`
	// ClientCertPath is the path to the read-only client certificate PEM.
	ClientCertPath string `hcl:"client_cert_path"`
	// ClientKeyPath is the path to the read-only client private key PEM.
	ClientKeyPath string `hcl:"client_key_path"`
	// ServerCertPath is the path to the Incus server certificate PEM used as a
	// trust anchor. Empty when ServerCertFingerprint is set.
	ServerCertPath string `hcl:"server_cert_path"`
	// ServerCertFingerprint is the SHA-256 hex fingerprint of the Incus server
	// certificate. Empty when ServerCertPath is set.
	ServerCertFingerprint string `hcl:"server_cert_fingerprint"`
	// DefaultProject is the Incus project used when a reference omits one.
	DefaultProject string `hcl:"default_project"`
	// RequestTimeout bounds every Incus call, written as a Go duration such as
	// "5s".
	RequestTimeout string `hcl:"request_timeout"`
}

// readerConfig validates the decoded plugin_data and converts it into the
// adapter's configuration. It fails loudly, naming every missing HCL key, so a
// misconfigured agent cannot start an attestor that silently cannot read Incus.
func (c *Config) readerConfig() (identity.Config, error) {
	var missing []string
	for key, value := range map[string]string{
		"server_url":       c.ServerURL,
		"client_cert_path": c.ClientCertPath,
		"client_key_path":  c.ClientKeyPath,
		"default_project":  c.DefaultProject,
		"request_timeout":  c.RequestTimeout,
	} {
		if strings.TrimSpace(value) == "" {
			missing = append(missing, key)
		}
	}

	if c.ServerCertPath == "" && c.ServerCertFingerprint == "" {
		missing = append(missing, "server_cert_path or server_cert_fingerprint")
	}

	if len(missing) > 0 {
		slices.Sort(missing)

		return identity.Config{}, status.Errorf(
			codes.InvalidArgument,
			"plugin_data is missing required values: %s",
			strings.Join(missing, ", "),
		)
	}

	if c.ServerCertPath != "" && c.ServerCertFingerprint != "" {
		return identity.Config{}, status.Error(
			codes.InvalidArgument,
			"plugin_data must set exactly one of server_cert_path and server_cert_fingerprint",
		)
	}

	timeout, err := time.ParseDuration(c.RequestTimeout)
	if err != nil {
		return identity.Config{}, status.Errorf(
			codes.InvalidArgument,
			"plugin_data request_timeout %q is not a duration",
			c.RequestTimeout,
		)
	}

	if timeout <= 0 {
		return identity.Config{}, status.Errorf(
			codes.InvalidArgument,
			"plugin_data request_timeout must be positive, got %q",
			c.RequestTimeout,
		)
	}

	return identity.Config{
		ServerURL:             c.ServerURL,
		ClientCertPEMPath:     c.ClientCertPath,
		ClientKeyPEMPath:      c.ClientKeyPath,
		ServerCertPEMPath:     c.ServerCertPath,
		ServerCertFingerprint: c.ServerCertFingerprint,
		DefaultProject:        attestor.ProjectName(c.DefaultProject),
		RequestTimeout:        timeout,
	}, nil
}

// Plugin serves the SPIRE WorkloadAttestor and Config services for Incus
// instance references. It holds the configured core behind a read-write lock
// because SPIRE may reconfigure a plugin concurrently with an RPC.
type Plugin struct {
	workloadattestorv1.UnimplementedWorkloadAttestorServer
	configv1.UnimplementedConfigServer

	// mtx guards core.
	mtx sync.RWMutex
	// core is the configured attestation core, nil until Configure succeeds.
	core deriver
	// logger is SPIRE's plugin logger, nil until SetLogger runs.
	logger hclog.Logger
}

// SetLogger receives the logger wired to SPIRE's own logging facilities. The
// plugin logs to it only; it never writes to stdout, which carries the
// go-plugin handshake.
func (p *Plugin) SetLogger(logger hclog.Logger) {
	p.logger = logger
}

// AttestReference attests the Incus instance named by the broker-submitted
// reference and returns unprefixed selector values.
//
// A reference whose type URL is not [referenceTypeURL] is InvalidArgument: this
// plugin implements reference attestation but does not own that type. SPIRE
// prefixes each returned value with the plugin name, so a value is
// "uuid:<value>" and the agent renders "incus:uuid:<value>".
func (p *Plugin) AttestReference(
	ctx context.Context,
	req *workloadattestorv1.AttestReferenceRequest,
) (*workloadattestorv1.AttestReferenceResponse, error) {
	core, err := p.currentCore()
	if err != nil {
		return nil, err
	}

	reference := req.GetReference()
	if reference.GetTypeUrl() != referenceTypeURL {
		return nil, status.Errorf(
			codes.InvalidArgument,
			"unsupported workload reference type %q",
			reference.GetTypeUrl(),
		)
	}

	claim := new(incusv1alpha1.IncusInstanceReference)
	if unmarshalErr := reference.UnmarshalTo(claim); unmarshalErr != nil {
		return nil, status.Error(
			codes.InvalidArgument,
			"workload reference is not a valid IncusInstanceReference",
		)
	}

	// The server claim is an expectation the core checks against the live Incus
	// endpoint; it is never a verified fact at this point.
	p.logDebug("attesting incus instance reference",
		"instance_uuid", claim.GetInstanceUuid(),
		"project", claim.GetProject(),
		"unverified_server_claim", claim.GetServer(),
	)

	selectors, err := core.Derive(ctx, attestor.Reference{
		InstanceUUID: attestor.InstanceUUID(claim.GetInstanceUuid()),
		Project:      attestor.ProjectName(claim.GetProject()),
		Generation:   attestor.GenerationUUID(claim.GetGenerationUuid()),
		Server:       claim.GetServer(),
	})
	if err != nil {
		return p.attestFailure(err)
	}

	values := make([]string, 0, len(selectors))
	for _, selector := range selectors {
		_, value := selector.TypeAndValue()
		values = append(values, value)
	}

	p.logDebug("attested incus instance reference", "selector_count", len(values))

	return &workloadattestorv1.AttestReferenceResponse{SelectorValues: values}, nil
}

// Configure decodes the agent's plugin_data HCL, builds the read-only Incus
// reader, and replaces the attestation core atomically.
func (p *Plugin) Configure(
	_ context.Context,
	req *configv1.ConfigureRequest,
) (*configv1.ConfigureResponse, error) {
	core, err := buildCore(req.GetHclConfiguration())
	if err != nil {
		return nil, err
	}

	p.mtx.Lock()
	p.core = core
	p.mtx.Unlock()

	p.logDebug("incus workload attestor configured")

	return &configv1.ConfigureResponse{}, nil
}

// Validate reports whether a candidate plugin_data block is usable. It builds
// the same reader Configure would build, so a bad URL, an unreadable
// certificate, or a malformed fingerprint is reported before a reconfigure.
func (p *Plugin) Validate(
	_ context.Context,
	req *configv1.ValidateRequest,
) (*configv1.ValidateResponse, error) {
	if _, err := buildCore(req.GetHclConfiguration()); err != nil {
		return &configv1.ValidateResponse{
			Valid: false,
			Notes: []string{status.Convert(err).Message()},
		}, nil
	}

	return &configv1.ValidateResponse{Valid: true, Notes: []string{"configuration valid"}}, nil
}

// attestFailure maps a core failure onto this plugin's gRPC answer:
//
//	[attestor.ErrInvalidReference]     InvalidArgument
//	[attestor.ErrInstanceNotFound]     no selectors and no error
//	[attestor.ErrAmbiguousReference]   PermissionDenied
//	[attestor.ErrGenerationMismatch]   PermissionDenied
//	[attestor.ErrEndpointMismatch]     PermissionDenied
//	[attestor.ErrUnusableRecord]       PermissionDenied
//	[attestor.ErrBackendUnauthorized]  FailedPrecondition
//	[attestor.ErrBackendPermanent]     FailedPrecondition
//	[attestor.ErrBackendUnavailable]   Unavailable
//	any other error                    Internal
//
// A missing instance is the documented "no selectors, no SVID" outcome rather
// than an error, because SPIRE mints no SVID for an empty selector set.
// Rejections carry a fixed message: the underlying text can name live Incus
// state, so it is logged at debug level and never returned to the caller.
//
// Only the transient backend class is Unavailable, because SPIRE preserves a
// plugin status through the Broker API and a Broker client retries Unavailable.
// An Incus credential refusal or a configuration fault would then be attempted
// once per Broker retry without any chance of a different answer, so both take
// FailedPrecondition: non-retryable, and distinct from the PermissionDenied
// this plugin already uses for an attestation denial. Reusing PermissionDenied
// would make a broken deployment indistinguishable from a workload that is not
// attestable.
func (p *Plugin) attestFailure(err error) (*workloadattestorv1.AttestReferenceResponse, error) {
	p.logDebug("incus attestation failed", "error", err.Error())

	switch {
	case errors.Is(err, attestor.ErrInstanceNotFound):
		return &workloadattestorv1.AttestReferenceResponse{}, nil
	case errors.Is(err, attestor.ErrInvalidReference):
		return nil, status.Error(codes.InvalidArgument, "invalid incus instance reference")
	case errors.Is(err, attestor.ErrAmbiguousReference),
		errors.Is(err, attestor.ErrGenerationMismatch),
		errors.Is(err, attestor.ErrEndpointMismatch),
		errors.Is(err, attestor.ErrUnusableRecord):
		return nil, status.Error(codes.PermissionDenied, "incus instance reference is not attestable")
	case errors.Is(err, attestor.ErrBackendUnauthorized):
		return nil, status.Error(codes.FailedPrecondition, "incus backend authorization failed")
	case errors.Is(err, attestor.ErrBackendPermanent):
		return nil, status.Error(codes.FailedPrecondition, "incus backend misconfigured")
	case errors.Is(err, attestor.ErrBackendUnavailable):
		return nil, status.Error(codes.Unavailable, "incus backend unavailable")
	default:
		return nil, status.Error(codes.Internal, "incus attestation failed")
	}
}

// currentCore returns the configured core, or FailedPrecondition when SPIRE has
// not called Configure yet.
func (p *Plugin) currentCore() (deriver, error) {
	p.mtx.RLock()
	defer p.mtx.RUnlock()

	if p.core == nil {
		return nil, status.Error(codes.FailedPrecondition, "plugin not configured")
	}

	return p.core, nil
}

// logDebug logs plugin detail through SPIRE's logger when one is attached.
// Selector values and rejection detail are debug-only; credential file contents
// are never read here, only their paths.
func (p *Plugin) logDebug(message string, args ...any) {
	if p.logger == nil {
		return
	}

	p.logger.Debug(message, args...)
}

// buildCore decodes plugin_data HCL, builds the read-only Incus identity
// adapter, and returns the core that reads through it. Every failure carries an
// InvalidArgument status so SPIRE reports a configuration fault, not a runtime
// one.
func buildCore(hclConfiguration string) (*attestor.Deriver, error) {
	config := new(Config)
	if err := hcl.Decode(config, hclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "plugin_data is not valid HCL: %v", err)
	}

	readerConfig, err := config.readerConfig()
	if err != nil {
		return nil, err
	}

	reader, err := identity.NewReader(readerConfig)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "incus reader is unusable: %v", err)
	}

	return attestor.NewDeriver(reader), nil
}

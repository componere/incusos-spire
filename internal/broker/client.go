package broker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	brokerv1 "github.com/spiffe/go-spiffe/v2/exp/proto/spiffe/broker"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	// securityHeaderKey is the metadata key SPIRE requires on every Broker call,
	// including reflection calls.
	securityHeaderKey = "broker.spiffe.io"
	// securityHeaderValue is the only value SPIRE accepts for securityHeaderKey.
	// SPIRE rejects any other value, and any repetition, with InvalidArgument.
	securityHeaderValue = "true"
	// unixScheme prefixes an absolute socket path to form a gRPC or Workload API
	// target.
	unixScheme = "unix://"
	// maxAttempts bounds the retry budget for transient transport failures (E3).
	maxAttempts = 3
	// allowlistDenialMarker is the fragment SPIRE 1.15.2 puts in its own
	// PermissionDenied message when a broker's SPIFFE ID may not use a
	// reference type, observed live as:
	//
	//	broker "spiffe://spike.incus.internal/incus-broker" is not allowed to
	//	use reference type "type.googleapis.com/..."
	//
	// It is the single version-pinned string in this package. If a later SPIRE
	// release rewords the denial, only this constant changes, and until it does
	// an unrecognized denial degrades to the honest [ErrPermissionDenied]
	// rather than to a false claim about the allowlist.
	allowlistDenialMarker = "is not allowed to use reference type"
)

var (
	// ErrInvalidRequest reports that the Broker endpoint rejected the request
	// arguments with gRPC InvalidArgument. In SPIRE 1.15.2 this covers a missing
	// or repeated "broker.spiffe.io: true" header ("security header missing from
	// request") and a request whose workload reference is absent or empty.
	ErrInvalidRequest = errors.New("broker rejected the request arguments")

	// ErrPermissionDenied reports gRPC PermissionDenied from the Broker
	// endpoint. The code alone does not say who denied the call: SPIRE returns
	// it when the reference type_url is outside allowed_reference_types, and a
	// workload attestor plugin returns it when its own policy rejects a
	// reference that it did attest. Match this sentinel whenever "the broker
	// refused to issue an SVID for this reference" is the answer you need.
	ErrPermissionDenied = errors.New("broker denied the workload reference")

	// ErrReferenceTypeDenied reports the one PermissionDenied this package can
	// attribute: the reference type_url is outside the allowed_reference_types
	// configured for this broker's SPIFFE ID, so authorization failed before
	// attestation and no workload attestor ran. Attribution comes from the
	// SPIRE message shape, see [allowlistDenialMarker]; an unattributable
	// denial stays [ErrPermissionDenied]. It wraps [ErrPermissionDenied], so
	// matching either sentinel works and only this one claims the cause.
	ErrReferenceTypeDenied = fmt.Errorf(
		"%w: the reference type is outside the broker allowlist",
		ErrPermissionDenied,
	)

	// ErrTransport reports a transport or TLS failure. An unauthorized broker
	// SPIFFE ID is rejected during the TLS handshake, so it surfaces here rather
	// than as a Broker API status.
	ErrTransport = errors.New("broker transport or TLS failure")

	// ErrTimeout reports that the call exceeded Config.RequestTimeout or the
	// caller's own deadline before an SVID arrived.
	ErrTimeout = errors.New("broker call timed out")

	// ErrNoSVID reports that the endpoint accepted the subscription but ended or
	// emptied the stream without delivering an X.509-SVID.
	ErrNoSVID = errors.New("broker delivered no X.509-SVID")
)

// SocketPath is an absolute filesystem path to a Unix domain socket.
type SocketPath string

// SPIFFEID is a SPIFFE ID in URI form, for example
// "spiffe://spike.incus.internal/incus-broker".
type SPIFFEID string

// TrustDomain is a SPIFFE trust domain name without a scheme, for example
// "spike.incus.internal".
type TrustDomain string

// X509SVID is one X.509-SVID delivered by the Broker API, converted out of the
// experimental proto types so callers never link them.
type X509SVID struct {
	// ID is the SPIFFE ID of the delivered SVID.
	ID SPIFFEID
	// ChainDER is the ASN.1 DER certificate chain, leaf first, not PEM.
	ChainDER []byte
	// KeyDER is the unencrypted PKCS#8 DER private key for ChainDER.
	KeyDER []byte
	// BundleDER is the ASN.1 DER X.509 bundle for the trust domain, not PEM.
	BundleDER []byte
	// Hint is the operator-supplied usage hint, empty when unset.
	Hint string
}

// Config is the connection material for one Broker API client. Every field is
// required except that exactly one of AgentID and AgentTrustDomain must
// authorize the endpoint.
type Config struct {
	// BrokerSocketPath is the agent's experimental.broker socket_path, the
	// mutual-TLS Unix socket this client dials.
	BrokerSocketPath SocketPath
	// WorkloadAPISocketPath is the agent Workload API socket used to obtain this
	// process's own broker X.509-SVID and trust bundle. SPIRE requires the two
	// sockets to live in unrelated directories, so this is never derived from
	// BrokerSocketPath.
	WorkloadAPISocketPath SocketPath
	// AgentID is the exact SPIFFE ID the Broker endpoint must present. Empty
	// when AgentTrustDomain is set.
	AgentID SPIFFEID
	// AgentTrustDomain authorizes any SPIFFE ID belonging to this trust domain.
	// Empty when AgentID is set.
	AgentTrustDomain TrustDomain
	// RequestTimeout bounds one Broker operation, retries included.
	RequestTimeout time.Duration
}

// Client performs Broker API operations over one mutual-TLS connection.
type Client struct {
	// api is the generated client for the experimental spiffe.broker.API service.
	api brokerv1.APIClient
	// conn is the owned connection to the broker socket. It is nil when the
	// connection belongs to the caller.
	conn *grpc.ClientConn
	// source supplies this process's X.509-SVID and bundle. It is nil when the
	// connection belongs to the caller.
	source *workloadapi.X509Source
	// timeout bounds one Broker operation.
	timeout time.Duration
}

// NewClient validates cfg, obtains the broker's own X.509-SVID from the
// Workload API, and returns a concrete [Client] bound to the broker socket.
//
// ctx bounds only the initial Workload API update; the returned Client does not
// retain it. Call [Client.Close] to release both the connection and the
// Workload API source.
func NewClient(ctx context.Context, cfg Config) (*Client, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	authorizer, err := buildAuthorizer(cfg)
	if err != nil {
		return nil, err
	}

	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(
		workloadapi.WithAddr(unixScheme+string(cfg.WorkloadAPISocketPath)),
	))
	if err != nil {
		return nil, fmt.Errorf("%w: obtain broker SVID from the Workload API: %w", ErrTransport, err)
	}

	tlsConfig := tlsconfig.MTLSClientConfig(source, source, authorizer)

	options := securityHeaderDialOptions()
	options = append(options, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))

	conn, err := grpc.NewClient(unixScheme+string(cfg.BrokerSocketPath), options...)
	if err != nil {
		return nil, errors.Join(
			fmt.Errorf("%w: dial broker socket: %w", ErrTransport, err),
			source.Close(),
		)
	}

	client := newClient(brokerv1.NewAPIClient(conn), cfg.RequestTimeout)
	client.conn = conn
	client.source = source

	return client, nil
}

// newClient wires api onto a [Client] that owns no transport resources.
func newClient(api brokerv1.APIClient, timeout time.Duration) *Client {
	return &Client{
		api:     api,
		conn:    nil,
		source:  nil,
		timeout: timeout,
	}
}

// FetchX509SVID subscribes to the X.509-SVID for reference, returns the first
// delivered SVID together with its trust bundle, then closes the stream.
//
// reference is the opaque workload reference. It is nested twice on the wire, as
// the Broker API requires: the Any goes inside a WorkloadReference, which goes
// inside SubscribeToX509SVIDRequest. The mandatory "broker.spiffe.io: true"
// header is attached by the connection's interceptors; omitting it makes SPIRE
// answer InvalidArgument, reported here as [ErrInvalidRequest]. Any refusal to
// issue an SVID for the reference yields [ErrPermissionDenied], and the subset
// SPIRE attributes to the broker's allowed_reference_types additionally yields
// [ErrReferenceTypeDenied].
//
// The whole operation is bounded by Config.RequestTimeout. Only an Unavailable
// transport failure is retried, at most [maxAttempts] times (E3); every other
// failure fails closed.
func (client *Client) FetchX509SVID(ctx context.Context, reference *anypb.Any) (X509SVID, error) {
	if reference.GetTypeUrl() == "" {
		return X509SVID{}, fmt.Errorf("%w: reference type URL is required", ErrInvalidRequest)
	}

	request := &brokerv1.SubscribeToX509SVIDRequest{
		Reference: &brokerv1.WorkloadReference{Reference: reference},
	}

	ctx, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()

	var last error
	for range maxAttempts {
		if err := ctx.Err(); err != nil {
			return X509SVID{}, classify(err)
		}

		svid, err := client.subscribeOnce(ctx, request)
		if err == nil {
			return svid, nil
		}

		last = err
		if !isTransient(err) {
			return X509SVID{}, err
		}
	}

	return X509SVID{}, last
}

// Close releases the broker connection and the Workload API source. It is safe
// to call on a Client that owns neither.
func (client *Client) Close() error {
	var errs []error

	if client.conn != nil {
		if err := client.conn.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close broker connection: %w", err))
		}
	}
	if client.source != nil {
		if err := client.source.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close Workload API source: %w", err))
		}
	}

	return errors.Join(errs...)
}

// subscribeOnce performs one SubscribeToX509SVID attempt and cancels the
// server-streaming call as soon as the first response arrives.
func (client *Client) subscribeOnce(
	ctx context.Context,
	request *brokerv1.SubscribeToX509SVIDRequest,
) (X509SVID, error) {
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	stream, err := client.api.SubscribeToX509SVID(streamCtx, request)
	if err != nil {
		return X509SVID{}, classify(err)
	}

	response, err := stream.Recv()
	if err != nil {
		return X509SVID{}, classify(err)
	}

	svids := response.GetSvids()
	if len(svids) == 0 {
		return X509SVID{}, fmt.Errorf("%w: response carried an empty SVID list", ErrNoSVID)
	}

	return convertSVID(svids[0]), nil
}

// securityHeaderDialOptions returns the interceptors that make the mandatory
// Broker security header structurally impossible to omit: every unary and
// streaming call on the connection carries it, whatever the caller's context.
func securityHeaderDialOptions() []grpc.DialOption {
	return []grpc.DialOption{
		grpc.WithUnaryInterceptor(attachSecurityHeaderUnary),
		grpc.WithStreamInterceptor(attachSecurityHeaderStream),
	}
}

// attachSecurityHeaderUnary adds the Broker security header to a unary call.
func attachSecurityHeaderUnary(
	ctx context.Context,
	method string,
	req, reply any,
	conn *grpc.ClientConn,
	invoker grpc.UnaryInvoker,
	opts ...grpc.CallOption,
) error {
	return invoker(withSecurityHeader(ctx), method, req, reply, conn, opts...)
}

// attachSecurityHeaderStream adds the Broker security header to a streaming call.
func attachSecurityHeaderStream(
	ctx context.Context,
	desc *grpc.StreamDesc,
	conn *grpc.ClientConn,
	method string,
	streamer grpc.Streamer,
	opts ...grpc.CallOption,
) (grpc.ClientStream, error) {
	return streamer(withSecurityHeader(ctx), desc, conn, method, opts...)
}

// withSecurityHeader sets exactly one "broker.spiffe.io: true" outgoing metadata
// value, replacing any value already present. SPIRE rejects a repeated header
// as harshly as a missing one.
func withSecurityHeader(ctx context.Context) context.Context {
	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		md = metadata.New(nil)
	} else {
		md = md.Copy()
	}
	md.Set(securityHeaderKey, securityHeaderValue)

	return metadata.NewOutgoingContext(ctx, md)
}

// convertSVID copies one experimental proto SVID into this package's own type.
func convertSVID(svid *brokerv1.X509SVID) X509SVID {
	return X509SVID{
		ID:        SPIFFEID(svid.GetSpiffeId()),
		ChainDER:  svid.GetX509Svid(),
		KeyDER:    svid.GetX509SvidKey(),
		BundleDER: svid.GetBundle(),
		Hint:      svid.GetHint(),
	}
}

// classify maps a Broker failure onto this package's sentinels using the status
// codes SPIRE 1.15.2 emits. A code with no documented Broker meaning keeps its
// gRPC status and gets no sentinel, so a caller cannot mistake it for one of the
// documented outcomes.
func classify(err error) error {
	if errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: broker closed the stream before sending one", ErrNoSVID)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%w: %w", ErrTimeout, err)
	}

	st, ok := status.FromError(err)
	if !ok {
		return fmt.Errorf("subscribe to X509-SVID: %w", err)
	}

	sentinel := sentinelForStatus(st)
	if sentinel == nil {
		return fmt.Errorf("subscribe to X509-SVID: %w", err)
	}

	return fmt.Errorf("%w: %w", sentinel, err)
}

// sentinelForStatus returns the sentinel documented for st, or nil when SPIRE
// 1.15.2 gives the code no Broker-specific meaning.
func sentinelForStatus(st *status.Status) error {
	code := st.Code()
	if code == codes.InvalidArgument {
		return ErrInvalidRequest
	}
	if code == codes.PermissionDenied {
		return permissionDeniedSentinel(st.Message())
	}
	if code == codes.DeadlineExceeded {
		return ErrTimeout
	}
	if code == codes.Unavailable || code == codes.Unauthenticated {
		return ErrTransport
	}

	return nil
}

// permissionDeniedSentinel attributes a PermissionDenied denial. SPIRE itself
// denies a reference type with a message of the shape
//
//	broker "spiffe://<domain>/<path>" is not allowed to use reference type "<type_url>"
//
// while a workload attestor plugin denies its own reference with whatever
// message that plugin chose, after it ran. Only the first shape justifies
// [ErrReferenceTypeDenied]; anything else stays [ErrPermissionDenied] rather
// than claiming a cause this package cannot observe.
func permissionDeniedSentinel(message string) error {
	if strings.Contains(message, allowlistDenialMarker) {
		return ErrReferenceTypeDenied
	}

	return ErrPermissionDenied
}

// isTransient reports the only retryable Broker failure: an Unavailable
// transport error, such as a broker socket that is not accepting connections
// yet. Argument, authorization, and timeout failures are never retried (E3).
func isTransient(err error) bool {
	return status.Code(err) == codes.Unavailable
}

// validateConfig fails closed on a missing socket path, missing or ambiguous
// endpoint authorization, or a non-positive timeout.
func validateConfig(cfg Config) error {
	if err := validateSocketPath("BrokerSocketPath", cfg.BrokerSocketPath); err != nil {
		return err
	}
	if err := validateSocketPath("WorkloadAPISocketPath", cfg.WorkloadAPISocketPath); err != nil {
		return err
	}

	idSet := strings.TrimSpace(string(cfg.AgentID)) != ""
	domainSet := strings.TrimSpace(string(cfg.AgentTrustDomain)) != ""
	if idSet == domainSet {
		return errors.New("exactly one of AgentID and AgentTrustDomain is required")
	}

	if cfg.RequestTimeout <= 0 {
		return errors.New("RequestTimeout must be positive")
	}

	return nil
}

// validateSocketPath requires a non-empty absolute path for the named field.
func validateSocketPath(field string, path SocketPath) error {
	trimmed := strings.TrimSpace(string(path))
	if trimmed == "" {
		return fmt.Errorf("%s is required", field)
	}
	if !filepath.IsAbs(trimmed) {
		return fmt.Errorf("%s must be an absolute path, got %q", field, trimmed)
	}

	return nil
}

// buildAuthorizer turns the configured expectation into a SPIFFE peer authorizer
// for the Broker endpoint's certificate. Hostname verification does not apply to
// an X.509-SVID, so the SPIFFE ID is the only server identity check.
func buildAuthorizer(cfg Config) (tlsconfig.Authorizer, error) {
	if strings.TrimSpace(string(cfg.AgentID)) != "" {
		id, err := spiffeid.FromString(string(cfg.AgentID))
		if err != nil {
			return nil, fmt.Errorf("parse AgentID: %w", err)
		}

		return tlsconfig.AuthorizeID(id), nil
	}

	domain, err := spiffeid.TrustDomainFromString(string(cfg.AgentTrustDomain))
	if err != nil {
		return nil, fmt.Errorf("parse AgentTrustDomain: %w", err)
	}

	return tlsconfig.AuthorizeMemberOf(domain), nil
}

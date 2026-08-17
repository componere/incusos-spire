package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	"github.com/spiffe/spire-plugin-sdk/plugintest"
	workloadattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/workloadattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/componere/incusos-spire/internal/attestor"
	"github.com/componere/incusos-spire/internal/attestor/mocks"
	incusv1alpha1 "github.com/componere/incusos-spire/proto/componere/incus/v1alpha1"
)

const (
	// liveUUID is the instance UUID captured from the P6 live evidence.
	liveUUID = "e9e6a2a0-d695-42d3-8e8c-92d290bfc7da"
	// liveGeneration is the matching volatile.uuid.generation.
	liveGeneration = "74957ed8-19bc-4d23-b76b-763bb6f8bb60"
	// otherGeneration is a generation produced by a later restore.
	otherGeneration = "50dd028f-da77-4f87-83e8-0773c72cbc05"
	// liveProject is the Incus project holding the instance.
	liveProject = "spike-uuid-lab"
	// liveName is the instance record name.
	liveName = "lab-c1r"
	// liveImage is volatile.base_image.
	liveImage = "f005c3b83cc4ffe5b0e0a0c3fccdee6decbae5559fafce9861d9c8b3d2720a16"
	// liveServerName is environment.server_name from GET /1.0.
	liveServerName = "ns1001912.ip-147-135-105.us"
	// liveFingerprint is environment.certificate_fingerprint from GET /1.0.
	liveFingerprint = "822b00ed474a2574d43223cbf34919b76a64946e145ec246aa4ae2e43318afdd"
	// selectorCount is the size of the frozen selector set.
	selectorCount = 6
	// certValidity is the lifetime of the throwaway client certificate.
	certValidity = time.Hour
	// incusServerURL is a syntactically valid Incus origin that is never dialed.
	incusServerURL = "https://incus.example:8443"
	// unreachableServerURL refuses connections immediately, so a served plugin
	// reaches the reader and reports backend unavailability without a live host.
	unreachableServerURL = "https://127.0.0.1:1"
)

// liveRecord returns the instance record captured from the live Incus host.
func liveRecord() attestor.InstanceRecord {
	return attestor.InstanceRecord{
		UUID:       liveUUID,
		Generation: liveGeneration,
		Project:    liveProject,
		Type:       attestor.InstanceTypeContainer,
		Status:     attestor.InstanceStatusRunning,
		Location:   "none",
		Image:      liveImage,
		Name:       liveName,
		CreatedAt:  "2026-08-16T23:32:37.236591866Z",
	}
}

// liveClaim returns the broker-submitted reference for the live instance.
func liveClaim() *incusv1alpha1.IncusInstanceReference {
	return &incusv1alpha1.IncusInstanceReference{
		InstanceUuid: liveUUID,
		Project:      liveProject,
	}
}

// packReference packs claim into the google.protobuf.Any SPIRE delivers.
func packReference(t *testing.T, claim *incusv1alpha1.IncusInstanceReference) *anypb.Any {
	t.Helper()

	packed, err := anypb.New(claim)
	require.NoError(t, err)

	return packed
}

// newPlugin returns a plugin whose core reads through reader.
func newPlugin(reader attestor.InstanceReader) *Plugin {
	return &Plugin{core: attestor.NewDeriver(reader)}
}

// attest runs AttestReference against a plugin backed by reader.
func attest(
	t *testing.T,
	reader attestor.InstanceReader,
	reference *anypb.Any,
) (*workloadattestorv1.AttestReferenceResponse, error) {
	t.Helper()

	return newPlugin(reader).AttestReference(
		t.Context(),
		&workloadattestorv1.AttestReferenceRequest{Reference: reference},
	)
}

func TestPackedReferenceUsesFrozenTypeURL(t *testing.T) {
	t.Parallel()

	require.Equal(t, referenceTypeURL, packReference(t, liveClaim()).GetTypeUrl())
}

func TestAttestReferenceReturnsUnprefixedSelectorValues(t *testing.T) {
	t.Parallel()

	reader := mocks.NewMockInstanceReader(t)
	reader.EXPECT().
		ReadInstanceByUUID(mock.Anything, attestor.InstanceUUID(liveUUID), attestor.ProjectName(liveProject)).
		Return(liveRecord(), nil).
		Once()

	response, err := attest(t, reader, packReference(t, liveClaim()))
	require.NoError(t, err)
	require.Equal(t, []string{
		"uuid:" + liveUUID,
		"generation:" + liveGeneration,
		"project:" + liveProject,
		"type:container",
		"name:" + liveName,
		"image:" + liveImage,
	}, response.GetSelectorValues())
	require.Len(t, response.GetSelectorValues(), selectorCount)

	for _, value := range response.GetSelectorValues() {
		require.NotContains(t, value, "incus:", "SPIRE adds the selector type from the plugin name")
	}
}

func TestAttestReferenceLogsDetailThroughSPIRELoggerAtDebugLevel(t *testing.T) {
	t.Parallel()

	reader := mocks.NewMockInstanceReader(t)
	reader.EXPECT().
		ReadInstanceByUUID(mock.Anything, mock.Anything, mock.Anything).
		Return(liveRecord(), nil).
		Once()

	logs := new(bytes.Buffer)
	plugin := newPlugin(reader)
	plugin.SetLogger(hclog.New(&hclog.LoggerOptions{
		DisableTime: true,
		Level:       hclog.Debug,
		Output:      logs,
	}))

	_, err := plugin.AttestReference(t.Context(), &workloadattestorv1.AttestReferenceRequest{
		Reference: packReference(t, liveClaim()),
	})
	require.NoError(t, err)
	require.Contains(t, logs.String(), "attested incus instance reference")
	require.Contains(t, logs.String(), "selector_count=6")
	require.Contains(t, logs.String(), "unverified_server_claim")
}

func TestAttestReferenceRejectsForeignTypeURL(t *testing.T) {
	t.Parallel()

	reader := mocks.NewMockInstanceReader(t)

	_, err := attest(t, reader, &anypb.Any{
		TypeUrl: "type.googleapis.com/spiffe.broker.WorkloadPIDReference",
	})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	reader.AssertNotCalled(t, "ReadInstanceByUUID", mock.Anything, mock.Anything, mock.Anything)
}

func TestAttestReferenceRejectsMissingReference(t *testing.T) {
	t.Parallel()

	_, err := attest(t, mocks.NewMockInstanceReader(t), nil)
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestAttestReferenceRejectsUndecodableReference(t *testing.T) {
	t.Parallel()

	_, err := attest(t, mocks.NewMockInstanceReader(t), &anypb.Any{
		TypeUrl: referenceTypeURL,
		Value:   []byte{0xff, 0xff, 0xff},
	})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestAttestReferenceRequiresConfiguration(t *testing.T) {
	t.Parallel()

	_, err := new(Plugin).AttestReference(
		t.Context(),
		&workloadattestorv1.AttestReferenceRequest{Reference: packReference(t, liveClaim())},
	)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
}

func TestAttestReferenceMapsCoreSentinels(t *testing.T) {
	t.Parallel()

	stoppedRecord := liveRecord()
	stoppedRecord.Status = attestor.InstanceStatusStopped

	otherProjectRecord := liveRecord()
	otherProjectRecord.Project = "other"

	tests := map[string]struct {
		claim    *incusv1alpha1.IncusInstanceReference
		setup    func(reader *mocks.MockInstanceReader)
		wantCode codes.Code
	}{
		"invalid reference": {
			claim:    &incusv1alpha1.IncusInstanceReference{InstanceUuid: "not-a-uuid"},
			setup:    func(_ *mocks.MockInstanceReader) {},
			wantCode: codes.InvalidArgument,
		},
		"instance not found": {
			claim: liveClaim(),
			setup: func(reader *mocks.MockInstanceReader) {
				reader.EXPECT().
					ReadInstanceByUUID(mock.Anything, mock.Anything, mock.Anything).
					Return(attestor.InstanceRecord{}, attestor.ErrInstanceNotFound).
					Once()
			},
			wantCode: codes.OK,
		},
		"ambiguous reference": {
			claim: liveClaim(),
			setup: func(reader *mocks.MockInstanceReader) {
				reader.EXPECT().
					ReadInstanceByUUID(mock.Anything, mock.Anything, mock.Anything).
					Return(attestor.InstanceRecord{}, fmt.Errorf(
						"identity: 2 instances match: %w",
						attestor.ErrAmbiguousReference,
					)).
					Once()
			},
			wantCode: codes.PermissionDenied,
		},
		"generation mismatch": {
			claim: &incusv1alpha1.IncusInstanceReference{
				InstanceUuid:   liveUUID,
				Project:        liveProject,
				GenerationUuid: otherGeneration,
			},
			setup: func(reader *mocks.MockInstanceReader) {
				reader.EXPECT().
					ReadInstanceByUUID(mock.Anything, mock.Anything, mock.Anything).
					Return(liveRecord(), nil).
					Once()
			},
			wantCode: codes.PermissionDenied,
		},
		"endpoint mismatch": {
			claim: &incusv1alpha1.IncusInstanceReference{
				InstanceUuid: liveUUID,
				Project:      liveProject,
				Server:       "impostor.example",
			},
			setup: func(reader *mocks.MockInstanceReader) {
				reader.EXPECT().
					ReadInstanceByUUID(mock.Anything, mock.Anything, mock.Anything).
					Return(liveRecord(), nil).
					Once()
				reader.EXPECT().
					ReadEndpointIdentity(mock.Anything).
					Return(attestor.EndpointIdentity{
						ServerName:             liveServerName,
						CertificateFingerprint: liveFingerprint,
					}, nil).
					Once()
			},
			wantCode: codes.PermissionDenied,
		},
		"unusable record status": {
			claim: liveClaim(),
			setup: func(reader *mocks.MockInstanceReader) {
				reader.EXPECT().
					ReadInstanceByUUID(mock.Anything, mock.Anything, mock.Anything).
					Return(stoppedRecord, nil).
					Once()
			},
			wantCode: codes.PermissionDenied,
		},
		"unusable record project": {
			claim: liveClaim(),
			setup: func(reader *mocks.MockInstanceReader) {
				reader.EXPECT().
					ReadInstanceByUUID(mock.Anything, mock.Anything, mock.Anything).
					Return(otherProjectRecord, nil).
					Once()
			},
			wantCode: codes.PermissionDenied,
		},
		"backend unavailable": {
			claim: liveClaim(),
			setup: func(reader *mocks.MockInstanceReader) {
				reader.EXPECT().
					ReadInstanceByUUID(mock.Anything, mock.Anything, mock.Anything).
					Return(attestor.InstanceRecord{}, errors.New("dial tcp 127.0.0.1:8443: connection refused")).
					Once()
			},
			wantCode: codes.Unavailable,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			reader := mocks.NewMockInstanceReader(t)
			test.setup(reader)

			response, err := attest(t, reader, packReference(t, test.claim))
			require.Equal(t, test.wantCode, status.Code(err))

			if test.wantCode != codes.OK {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)
			require.Empty(t, response.GetSelectorValues())
		})
	}
}

func TestAttestFailureHidesBackendDetailAndMapsUnknownError(t *testing.T) {
	t.Parallel()

	plugin := new(Plugin)

	_, err := plugin.attestFailure(fmt.Errorf(
		"attestor: expected generation %q does not match live generation %q: %w",
		otherGeneration,
		liveGeneration,
		attestor.ErrGenerationMismatch,
	))
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	require.NotContains(t, status.Convert(err).Message(), liveGeneration)

	_, err = plugin.attestFailure(errors.New("boom"))
	require.Equal(t, codes.Internal, status.Code(err))
}

func TestReaderConfigRejectsIncompleteConfig(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		mutate   func(config *Config)
		wantText string
	}{
		"missing server url": {
			mutate:   func(config *Config) { config.ServerURL = "" },
			wantText: "server_url",
		},
		"missing client cert": {
			mutate:   func(config *Config) { config.ClientCertPath = "" },
			wantText: "client_cert_path",
		},
		"missing client key": {
			mutate:   func(config *Config) { config.ClientKeyPath = "" },
			wantText: "client_key_path",
		},
		"missing project": {
			mutate:   func(config *Config) { config.DefaultProject = "" },
			wantText: "default_project",
		},
		"missing timeout": {
			mutate:   func(config *Config) { config.RequestTimeout = "" },
			wantText: "request_timeout",
		},
		"missing server pin": {
			mutate:   func(config *Config) { config.ServerCertFingerprint = "" },
			wantText: "server_cert_path or server_cert_fingerprint",
		},
		"both server pins": {
			mutate:   func(config *Config) { config.ServerCertPath = "/tmp/server.pem" },
			wantText: "exactly one of server_cert_path and server_cert_fingerprint",
		},
		"unparsable timeout": {
			mutate:   func(config *Config) { config.RequestTimeout = "soon" },
			wantText: "is not a duration",
		},
		"non positive timeout": {
			mutate:   func(config *Config) { config.RequestTimeout = "0s" },
			wantText: "must be positive",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			config := completeConfig("/tmp/client.pem", "/tmp/client-key.pem")
			test.mutate(&config)

			_, err := config.readerConfig()
			require.Equal(t, codes.InvalidArgument, status.Code(err))
			require.Contains(t, status.Convert(err).Message(), test.wantText)
		})
	}
}

func TestReaderConfigConvertsEveryValue(t *testing.T) {
	t.Parallel()

	config := completeConfig("/tmp/client.pem", "/tmp/client-key.pem")

	readerConfig, err := config.readerConfig()
	require.NoError(t, err)
	require.Equal(t, config.ServerURL, readerConfig.ServerURL)
	require.Equal(t, config.ClientCertPath, readerConfig.ClientCertPEMPath)
	require.Equal(t, config.ClientKeyPath, readerConfig.ClientKeyPEMPath)
	require.Equal(t, config.ServerCertFingerprint, readerConfig.ServerCertFingerprint)
	require.Empty(t, readerConfig.ServerCertPEMPath)
	require.Equal(t, attestor.ProjectName(liveProject), readerConfig.DefaultProject)
	require.Equal(t, 5*time.Second, readerConfig.RequestTimeout)
}

func TestConfigureBuildsCoreFromPluginData(t *testing.T) {
	t.Parallel()

	certPath, keyPath := writeClientKeypair(t)
	plugin := new(Plugin)

	_, err := plugin.Configure(t.Context(), &configv1.ConfigureRequest{
		HclConfiguration: pluginDataHCL(certPath, keyPath, incusServerURL),
	})
	require.NoError(t, err)

	core, err := plugin.currentCore()
	require.NoError(t, err)
	require.NotNil(t, core)
}

func TestConfigureRejectsBadPluginData(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"malformed hcl":  `server_url = `,
		"empty block":    ``,
		"unusable value": `server_url = "http://incus.example:8443"`,
	}

	for name, hclConfiguration := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := new(Plugin).Configure(t.Context(), &configv1.ConfigureRequest{
				HclConfiguration: hclConfiguration,
			})
			require.Equal(t, codes.InvalidArgument, status.Code(err))
		})
	}
}

func TestValidateReportsUsability(t *testing.T) {
	t.Parallel()

	certPath, keyPath := writeClientKeypair(t)
	plugin := new(Plugin)

	valid, err := plugin.Validate(t.Context(), &configv1.ValidateRequest{
		HclConfiguration: pluginDataHCL(certPath, keyPath, incusServerURL),
	})
	require.NoError(t, err)
	require.True(t, valid.GetValid())

	invalid, err := plugin.Validate(t.Context(), &configv1.ValidateRequest{HclConfiguration: ""})
	require.NoError(t, err)
	require.False(t, invalid.GetValid())
	require.NotEmpty(t, invalid.GetNotes())

	// Validate must not configure the plugin.
	_, err = plugin.currentCore()
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
}

func TestServedPluginAnswersOverGoPluginTransport(t *testing.T) {
	certPath, keyPath := writeClientKeypair(t)
	plugin := new(Plugin)
	logs := new(bytes.Buffer)
	attestorClient := new(workloadattestorv1.WorkloadAttestorPluginClient)
	configClient := new(configv1.ConfigServiceClient)

	plugintest.ServeInBackground(t, plugintest.Config{
		PluginServer:       workloadattestorv1.WorkloadAttestorPluginServer(plugin),
		PluginClient:       attestorClient,
		ServiceServers:     []pluginsdk.ServiceServer{configv1.ConfigServiceServer(plugin)},
		ServiceClients:     []pluginsdk.ServiceClient{configClient},
		HostServiceServers: nil,
		Logger: hclog.New(&hclog.LoggerOptions{
			DisableTime: true,
			Level:       hclog.Info,
			Output:      logs,
		}),
	})

	request := &workloadattestorv1.AttestReferenceRequest{Reference: packReference(t, liveClaim())}

	_, err := attestorClient.AttestReference(t.Context(), request)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))

	require.NotNil(t, plugin.logger, "SPIRE must inject its logger through SetLogger")

	_, err = configClient.Configure(t.Context(), &configv1.ConfigureRequest{
		CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: "spike.incus.internal"},
		HclConfiguration:  pluginDataHCL(certPath, keyPath, unreachableServerURL),
	})
	require.NoError(t, err)

	_, err = attestorClient.AttestReference(t.Context(), &workloadattestorv1.AttestReferenceRequest{
		Reference: &anypb.Any{TypeUrl: "type.googleapis.com/spiffe.broker.WorkloadPIDReference"},
	})
	require.Equal(t, codes.InvalidArgument, status.Code(err))

	_, err = attestorClient.AttestReference(t.Context(), request)
	require.Equal(t, codes.Unavailable, status.Code(err))

	// Legacy PID attestation is intentionally left to the embedded server.
	_, err = attestorClient.Attest(t.Context(), &workloadattestorv1.AttestRequest{Pid: 1})
	require.Equal(t, codes.Unimplemented, status.Code(err))

	require.NotContains(t, logs.String(), liveUUID, "reference detail must stay below info level")
	require.NotContains(t, logs.String(), "uuid:", "selector values must stay below info level")
}

// completeConfig returns a plugin_data value that passes validation.
func completeConfig(certPath, keyPath string) Config {
	return Config{
		ServerURL:             incusServerURL,
		ClientCertPath:        certPath,
		ClientKeyPath:         keyPath,
		ServerCertPath:        "",
		ServerCertFingerprint: liveFingerprint,
		DefaultProject:        liveProject,
		RequestTimeout:        "5s",
	}
}

// pluginDataHCL renders the agent's plugin_data body for the given keypair and
// Incus origin.
func pluginDataHCL(certPath, keyPath, serverURL string) string {
	config := completeConfig(certPath, keyPath)
	config.ServerURL = serverURL

	return strings.Join([]string{
		fmt.Sprintf("server_url = %q", config.ServerURL),
		fmt.Sprintf("client_cert_path = %q", config.ClientCertPath),
		fmt.Sprintf("client_key_path = %q", config.ClientKeyPath),
		fmt.Sprintf("server_cert_fingerprint = %q", config.ServerCertFingerprint),
		fmt.Sprintf("default_project = %q", config.DefaultProject),
		fmt.Sprintf("request_timeout = %q", config.RequestTimeout),
	}, "\n")
}

// writeClientKeypair writes a throwaway client certificate and key so the
// identity adapter can load real TLS material during configuration.
func writeClientKeypair(t *testing.T) (string, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "attestor-ro"},
		NotBefore:    time.Now().Add(-certValidity),
		NotAfter:     time.Now().Add(certValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.pem")
	keyPath := filepath.Join(dir, "client-key.pem")

	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	}), 0o600))
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDER,
	}), 0o600))

	return certPath, keyPath
}

package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/componere/incusos-spire/internal/attestor"
)

const (
	capturedUUID           attestor.InstanceUUID     = "e9e6a2a0-d695-42d3-8e8c-92d290bfc7da"
	capturedGeneration     attestor.GenerationUUID   = "e9e6a2a0-d695-42d3-8e8c-92d290bfc7da"
	capturedProject        attestor.ProjectName      = "spike-uuid-lab"
	capturedName           attestor.InstanceName     = "lab-c1r"
	capturedImage          attestor.ImageFingerprint = "f005c3b83cc4ffe5b0e0a0c3fccdee6decbae5559fafce9861d9c8b3d2720a16"
	capturedCreatedAt      attestor.CreatedAt        = "2026-08-16T23:32:37.236591866Z"
	capturedServerName                               = "ns1001912.ip-147-135-105.us"
	capturedServerFP                                 = "822b00ed474a2574d43223cbf34919b76a64946e145ec246aa4ae2e43318afdd"
	duplicateUUID          attestor.InstanceUUID     = "f09e831b-fd6a-40fa-928a-d13c35d5959e"
	shortCallTimeout                                 = 40 * time.Millisecond
	blockLongerThanTimeout                           = time.Second
	firstCall              int32                     = 1
	retriedAtLeast         int32                     = 2
	pemFileMode                                      = 0o600
	serialBitLength                                  = 128
)

// testEnv is the shared TLS httptest fixture for Reader tests.
type testEnv struct {
	// reader is the subject under test.
	reader *Reader
	// server is the Incus-shaped TLS origin.
	server *httptest.Server
	// files holds the throwaway PEM paths.
	files pemFiles
}

// pemFiles is the on-disk TLS material passed to [NewReader].
type pemFiles struct {
	// clientCert is the attestor-ro certificate path.
	clientCert string
	// clientKey is the attestor-ro key path.
	clientKey string
	// serverCert is the Incus server certificate path.
	serverCert string
	// fingerprint is the SHA-256 of the server certificate.
	fingerprint string
}

func TestReadInstanceByUUIDMapsCapturedRecord(t *testing.T) {
	t.Parallel()

	var gotQuery atomic.Value
	env := newTestEnv(t, func(writer http.ResponseWriter, req *http.Request) {
		gotQuery.Store(req.URL.RawQuery)
		assert.Equal(t, http.MethodGet, req.Method)
		assert.Equal(t, instancesPath, req.URL.Path)
		writeEnvelope(t, writer, []any{capturedInstance()})
	})

	got, err := env.reader.ReadInstanceByUUID(t.Context(), capturedUUID, capturedProject)
	require.NoError(t, err)

	assert.Equal(t, attestor.InstanceRecord{
		UUID:       capturedUUID,
		Generation: capturedGeneration,
		Project:    capturedProject,
		Type:       attestor.InstanceTypeContainer,
		Status:     attestor.InstanceStatusRunning,
		Location:   "none",
		Image:      capturedImage,
		Name:       capturedName,
		CreatedAt:  capturedCreatedAt,
	}, got)

	rawQuery, ok := gotQuery.Load().(string)
	require.True(t, ok)
	values, err := url.ParseQuery(rawQuery)
	require.NoError(t, err)
	assert.Equal(t, recursionLevel, values.Get("recursion"))
	assert.Equal(t, string(capturedProject), values.Get("project"))
	assert.Equal(t, uuidFilterPrefix+string(capturedUUID), values.Get("filter"))
}

func TestReadInstanceByUUIDErrorTaxonomy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		instances []any
		uuid      attestor.InstanceUUID
		wantErr   error
		contains  string
	}{
		{
			name:      "zero results are not found",
			instances: []any{},
			uuid:      capturedUUID,
			wantErr:   attestor.ErrInstanceNotFound,
		},
		{
			name: "two results are ambiguous and never chosen",
			instances: []any{
				capturedInstanceNamed("lab-c2", duplicateUUID),
				capturedInstanceNamed("lab-c3", duplicateUUID),
			},
			uuid:     duplicateUUID,
			wantErr:  attestor.ErrAmbiguousReference,
			contains: "2",
		},
		{
			name: "empty volatile.uuid is unusable",
			instances: []any{
				capturedInstanceWithUUID(""),
			},
			uuid:    capturedUUID,
			wantErr: attestor.ErrUnusableRecord,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			env := newTestEnv(t, func(writer http.ResponseWriter, req *http.Request) {
				assert.Equal(t, http.MethodGet, req.Method)
				writeEnvelope(t, writer, tt.instances)
			})

			got, err := env.reader.ReadInstanceByUUID(t.Context(), tt.uuid, "")
			require.Error(t, err)
			require.ErrorIs(t, err, tt.wantErr)
			assert.Equal(t, attestor.InstanceRecord{}, got)
			if tt.contains != "" {
				assert.Contains(t, err.Error(), tt.contains)
			}
		})
	}
}

func TestReadInstanceByUUIDUsesDefaultProjectWhenEmpty(t *testing.T) {
	t.Parallel()

	var gotProject atomic.Value
	env := newTestEnv(t, func(writer http.ResponseWriter, req *http.Request) {
		gotProject.Store(req.URL.Query().Get("project"))
		writeEnvelope(t, writer, []any{capturedInstance()})
	})

	_, err := env.reader.ReadInstanceByUUID(t.Context(), capturedUUID, "")
	require.NoError(t, err)
	assert.Equal(t, string(capturedProject), gotProject.Load())
}

func TestReadEndpointIdentityMapsServerEnvironment(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t, func(writer http.ResponseWriter, req *http.Request) {
		assert.Equal(t, http.MethodGet, req.Method)
		assert.Equal(t, serverPath, req.URL.Path)
		writeEnvelope(t, writer, map[string]any{
			"environment": map[string]any{
				"server_name":             capturedServerName,
				"certificate_fingerprint": capturedServerFP,
			},
		})
	})

	got, err := env.reader.ReadEndpointIdentity(t.Context())
	require.NoError(t, err)
	assert.Equal(t, attestor.EndpointIdentity{
		ServerName:             capturedServerName,
		CertificateFingerprint: capturedServerFP,
	}, got)
}

func TestReadInstanceByUUIDTimeoutIsBackendUnavailable(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t, func(writer http.ResponseWriter, req *http.Request) {
		select {
		case <-req.Context().Done():
			return
		case <-time.After(blockLongerThanTimeout):
			writeEnvelope(t, writer, []any{capturedInstance()})
		}
	}, func(cfg *Config) {
		cfg.RequestTimeout = shortCallTimeout
	})

	got, err := env.reader.ReadInstanceByUUID(t.Context(), capturedUUID, capturedProject)
	require.Error(t, err)
	require.ErrorIs(t, err, attestor.ErrBackendUnavailable)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Equal(t, attestor.InstanceRecord{}, got)
}

func TestReadEndpointIdentityTLSPinFailureIsBackendUnavailable(t *testing.T) {
	t.Parallel()

	handler := func(writer http.ResponseWriter, _ *http.Request) {
		writeEnvelope(t, writer, map[string]any{"environment": map[string]any{}})
	}
	server := httptest.NewTLSServer(http.HandlerFunc(handler))
	t.Cleanup(server.Close)

	files := writeClientPEMs(t)
	files.fingerprint = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	reader, err := NewReader(Config{
		ServerURL:             server.URL,
		ClientCertPEMPath:     files.clientCert,
		ClientKeyPEMPath:      files.clientKey,
		ServerCertFingerprint: files.fingerprint,
		DefaultProject:        capturedProject,
		RequestTimeout:        time.Second,
	})
	require.NoError(t, err)

	got, err := reader.ReadEndpointIdentity(t.Context())
	require.Error(t, err)
	require.ErrorIs(t, err, attestor.ErrBackendUnavailable)
	assert.Equal(t, attestor.EndpointIdentity{}, got)
}

func TestReadEndpointIdentityTransportFailureIsBackendUnavailable(t *testing.T) {
	t.Parallel()

	files := writeClientPEMs(t)
	serverCert, err := generateSelfSignedCert()
	require.NoError(t, err)
	files.serverCert = writeFile(t, "server.crt", serverCert.certPEM)

	reader, err := NewReader(Config{
		ServerURL:         "https://127.0.0.1:1",
		ClientCertPEMPath: files.clientCert,
		ClientKeyPEMPath:  files.clientKey,
		ServerCertPEMPath: files.serverCert,
		DefaultProject:    capturedProject,
		RequestTimeout:    shortCallTimeout,
	})
	require.NoError(t, err)

	got, err := reader.ReadEndpointIdentity(t.Context())
	require.Error(t, err)
	require.ErrorIs(t, err, attestor.ErrBackendUnavailable)
	assert.Equal(t, attestor.EndpointIdentity{}, got)
}

func TestReadInstanceByUUIDDoesNotRetryAuthorizationFailure(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	env := newTestEnv(t, func(writer http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		writer.WriteHeader(http.StatusForbidden)
	})

	_, err := env.reader.ReadInstanceByUUID(t.Context(), capturedUUID, capturedProject)
	require.Error(t, err)
	require.ErrorIs(t, err, attestor.ErrBackendUnavailable)
	assert.Equal(t, firstCall, calls.Load())
}

func TestReadInstanceByUUIDRetriesTransientTransportError(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	env := newTestEnv(t, func(writer http.ResponseWriter, req *http.Request) {
		if calls.Add(1) == firstCall {
			hijacker, ok := writer.(http.Hijacker)
			assert.True(t, ok)
			if !ok {
				return
			}
			conn, _, err := hijacker.Hijack()
			assert.NoError(t, err)
			if err != nil {
				return
			}
			assert.NoError(t, conn.Close())

			return
		}

		assert.Equal(t, instancesPath, req.URL.Path)
		writeEnvelope(t, writer, []any{capturedInstance()})
	})

	got, err := env.reader.ReadInstanceByUUID(t.Context(), capturedUUID, capturedProject)
	require.NoError(t, err)
	assert.Equal(t, capturedUUID, got.UUID)
	assert.GreaterOrEqual(t, calls.Load(), retriedAtLeast)
}

func TestNewReaderValidatesConfig(t *testing.T) {
	t.Parallel()

	files := writeClientPEMs(t)
	serverCert, err := generateSelfSignedCert()
	require.NoError(t, err)
	files.serverCert = writeFile(t, "server.crt", serverCert.certPEM)
	files.fingerprint = fingerprintOf(serverCert.cert.Raw)

	valid := Config{
		ServerURL:         "https://127.0.0.1:8443",
		ClientCertPEMPath: files.clientCert,
		ClientKeyPEMPath:  files.clientKey,
		ServerCertPEMPath: files.serverCert,
		DefaultProject:    capturedProject,
		RequestTimeout:    time.Second,
	}

	tests := []struct {
		name    string
		mutate  func(cfg Config) Config
		wantErr string
	}{
		{
			name: "missing server URL",
			mutate: func(cfg Config) Config {
				cfg.ServerURL = ""
				return cfg
			},
			wantErr: "ServerURL is required",
		},
		{
			name: "http is rejected",
			mutate: func(cfg Config) Config {
				cfg.ServerURL = "http://127.0.0.1:8443"
				return cfg
			},
			wantErr: "https origin",
		},
		{
			name: "missing default project",
			mutate: func(cfg Config) Config {
				cfg.DefaultProject = ""
				return cfg
			},
			wantErr: "DefaultProject is required",
		},
		{
			name: "zero timeout",
			mutate: func(cfg Config) Config {
				cfg.RequestTimeout = 0
				return cfg
			},
			wantErr: "RequestTimeout must be positive",
		},
		{
			name: "both server pins",
			mutate: func(cfg Config) Config {
				cfg.ServerCertFingerprint = files.fingerprint
				return cfg
			},
			wantErr: "exactly one of ServerCertPEMPath and ServerCertFingerprint",
		},
		{
			name: "neither server pin",
			mutate: func(cfg Config) Config {
				cfg.ServerCertPEMPath = ""
				return cfg
			},
			wantErr: "exactly one of ServerCertPEMPath and ServerCertFingerprint",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := NewReader(tt.mutate(valid))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestNewReaderAcceptsFingerprintPin(t *testing.T) {
	t.Parallel()

	handler := func(writer http.ResponseWriter, _ *http.Request) {
		writeEnvelope(t, writer, map[string]any{
			"environment": map[string]any{
				"server_name":             capturedServerName,
				"certificate_fingerprint": capturedServerFP,
			},
		})
	}
	server := httptest.NewTLSServer(http.HandlerFunc(handler))
	t.Cleanup(server.Close)

	files := writeClientPEMs(t)
	sum := sha256.Sum256(server.Certificate().Raw)

	reader, err := NewReader(Config{
		ServerURL:             server.URL,
		ClientCertPEMPath:     files.clientCert,
		ClientKeyPEMPath:      files.clientKey,
		ServerCertFingerprint: hex.EncodeToString(sum[:]),
		DefaultProject:        capturedProject,
		RequestTimeout:        time.Second,
	})
	require.NoError(t, err)

	got, err := reader.ReadEndpointIdentity(t.Context())
	require.NoError(t, err)
	assert.Equal(t, capturedServerName, got.ServerName)
}

// newTestEnv starts a TLS httptest server that speaks Incus-shaped JSON.
func newTestEnv(t *testing.T, handler http.HandlerFunc, mutators ...func(*Config)) *testEnv {
	t.Helper()

	server := httptest.NewUnstartedServer(handler)
	server.StartTLS()
	t.Cleanup(server.Close)

	files := writeClientPEMs(t)
	files.serverCert = writeFile(t, "server.crt", pemEncode("CERTIFICATE", server.Certificate().Raw))

	cfg := Config{
		ServerURL:         server.URL,
		ClientCertPEMPath: files.clientCert,
		ClientKeyPEMPath:  files.clientKey,
		ServerCertPEMPath: files.serverCert,
		DefaultProject:    capturedProject,
		RequestTimeout:    time.Second,
	}
	for _, mutate := range mutators {
		mutate(&cfg)
	}

	reader, err := NewReader(cfg)
	require.NoError(t, err)

	return &testEnv{reader: reader, server: server, files: files}
}

// writeEnvelope writes a successful Incus sync envelope.
func writeEnvelope(t *testing.T, writer http.ResponseWriter, metadata any) {
	t.Helper()

	body, err := json.Marshal(map[string]any{
		"type":        "sync",
		"status":      "Success",
		"status_code": http.StatusOK,
		"error_code":  0,
		"error":       "",
		"metadata":    metadata,
	})
	require.NoError(t, err)
	writer.Header().Set("Content-Type", "application/json")
	_, err = writer.Write(body)
	require.NoError(t, err)
}

// capturedInstance is the P6 lab-c1r fixture.
func capturedInstance() map[string]any {
	return capturedInstanceNamed(string(capturedName), capturedUUID)
}

// capturedInstanceNamed is a captured-shaped instance with a chosen name and uuid.
func capturedInstanceNamed(name string, instanceUUID attestor.InstanceUUID) map[string]any {
	return capturedInstanceWithUUID(string(instanceUUID), name)
}

// capturedInstanceWithUUID is a captured-shaped instance with a chosen volatile.uuid.
func capturedInstanceWithUUID(instanceUUID string, name ...string) map[string]any {
	instanceName := string(capturedName)
	if len(name) > 0 {
		instanceName = name[0]
	}

	return map[string]any{
		"architecture": "x86_64",
		"config": map[string]any{
			"volatile.base_image":       string(capturedImage),
			"volatile.uuid":             instanceUUID,
			"volatile.uuid.generation":  string(capturedGeneration),
			"volatile.last_state.power": "RUNNING",
		},
		"created_at": string(capturedCreatedAt),
		"type":       "container",
		"location":   "none",
		"name":       instanceName,
		"project":    string(capturedProject),
		"status":     "Running",
	}
}

// writeClientPEMs writes a throwaway client certificate and key into t.TempDir.
func writeClientPEMs(t *testing.T) pemFiles {
	t.Helper()

	pair, err := generateSelfSignedCert()
	require.NoError(t, err)

	return pemFiles{
		clientCert: writeFile(t, "client.crt", pair.certPEM),
		clientKey:  writeFile(t, "client.key", pair.keyPEM),
	}
}

// writeFile writes content into a uniquely named file under t.TempDir.
func writeFile(t *testing.T, name string, content []byte) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, content, pemFileMode))

	return path
}

// certPair is a throwaway self-signed certificate used by tests.
type certPair struct {
	// cert is the parsed certificate.
	cert *x509.Certificate
	// certPEM is the certificate PEM.
	certPEM []byte
	// keyPEM is the PKCS#8 private key PEM.
	keyPEM []byte
}

// generateSelfSignedCert returns a one-hour self-signed certificate for tests.
func generateSelfSignedCert() (certPair, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return certPair{}, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), serialBitLength))
	if err != nil {
		return certPair{}, err
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "identity-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return certPair{}, err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return certPair{}, err
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return certPair{}, err
	}

	return certPair{
		cert:    cert,
		certPEM: pemEncode("CERTIFICATE", der),
		keyPEM:  pemEncode("PRIVATE KEY", keyBytes),
	}, nil
}

// pemEncode encodes der as a PEM block of blockType.
func pemEncode(blockType string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
}

// fingerprintOf returns the SHA-256 hex of a certificate DER.
func fingerprintOf(raw []byte) string {
	sum := sha256.Sum256(raw)

	return hex.EncodeToString(sum[:])
}

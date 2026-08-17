package bootstrap

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
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/componere/incusos-spire/internal/attestor"
	"github.com/componere/incusos-spire/internal/nonce"
)

// Writer satisfies the consumer-owned port in internal/nonce. The assertion
// lives in the test binary so the adapter's production code carries no
// dependency on its consumer.
var _ nonce.BootstrapWriter = (*Writer)(nil)

const (
	testProject  attestor.ProjectName  = "spike-spiffe"
	testInstance attestor.InstanceName = "spike-guest-a"
	// testPayload stands in for the bootstrap document. It is a fixture, not a
	// secret, and it is deliberately distinctive so a leak test can find it.
	testPayload = `{"nonce":"FIXTURE-NONCE-VALUE-0123456789","nonce-id":"n-1"}`
	// testOperationID is the operation UUID used by the async fixtures.
	testOperationID = "884e259c-9483-4cee-8af4-ff32b15cd1f5"

	instancePath  = instancesPath + "/" + string(testInstance)
	operationPath = operationsPath + "/" + testOperationID + "/" + waitSegment
	operationURL  = operationsPath + "/" + testOperationID
	// contentTypeValue is the JSON media type. The name avoids "json" because
	// testifylint reads such a name as an encoded-payload comparison.
	contentTypeValue = "application/json"
	firstCall        = int32(1)
	retriedAtLeast   = int32(2)

	shortCallTimeout       = 40 * time.Millisecond
	blockLongerThanTimeout = time.Second
	waitCallTimeout        = 5 * time.Second
	pemFileMode            = 0o600
	serialBitLength        = 128
)

// testEnv is the shared TLS httptest fixture for [Writer] tests.
type testEnv struct {
	// writer is the subject under test.
	writer *Writer
	// requests records every request the server received.
	requests *recorder
	// files holds the throwaway PEM paths.
	files pemFiles
}

// recorder captures the requests a test server received.
type recorder struct {
	// mutex guards calls.
	mutex sync.Mutex
	// calls is every observed request, in order.
	calls []capturedRequest
}

// capturedRequest is one observed request.
type capturedRequest struct {
	// method is the HTTP method.
	method string
	// path is the URL path.
	path string
	// query is the parsed query string.
	query map[string]string
	// body is the verbatim request body.
	body string
	// contentType is the request Content-Type header.
	contentType string
}

// pemFiles is the on-disk TLS material passed to [NewWriter].
type pemFiles struct {
	// clientCert is the bootstrap-writer certificate path.
	clientCert string
	// clientKey is the bootstrap-writer key path.
	clientKey string
	// serverCert is the Incus server certificate path.
	serverCert string
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

func TestWriteBootstrapSendsOneRawPatch(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t, func(writer http.ResponseWriter, _ *http.Request) {
		writeSyncEnvelope(t, writer)
	})

	require.NoError(t, env.writer.WriteBootstrap(t.Context(), testProject, testInstance, testPayload))

	calls := env.requests.snapshot()
	require.Len(t, calls, 1, "a bootstrap write is exactly one request")
	assert.Equal(t, http.MethodPatch, calls[0].method)
	assert.Equal(t, instancePath, calls[0].path)
	assert.Equal(t, map[string]string{"project": string(testProject)}, calls[0].query)
	assert.Equal(t, contentTypeValue, calls[0].contentType)
	assert.JSONEq(t, `{"config":{"user.spiffe-bootstrap":`+strconv.Quote(testPayload)+`}}`, calls[0].body)
}

func TestClearBootstrapSendsTheSamePatchWithAnEmptyValue(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t, func(writer http.ResponseWriter, _ *http.Request) {
		writeSyncEnvelope(t, writer)
	})

	require.NoError(t, env.writer.ClearBootstrap(t.Context(), testProject, testInstance))

	calls := env.requests.snapshot()
	require.Len(t, calls, 1, "a bootstrap clear is exactly one request")
	assert.Equal(t, http.MethodPatch, calls[0].method)
	assert.Equal(t, instancePath, calls[0].path)
	assert.Equal(t, map[string]string{"project": string(testProject)}, calls[0].query)
	assert.JSONEq(t, `{"config":{"user.spiffe-bootstrap":""}}`, calls[0].body)
}

func TestBootstrapUsesTheConfiguredProjectWhenTheCallerOmitsIt(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t, func(writer http.ResponseWriter, _ *http.Request) {
		writeSyncEnvelope(t, writer)
	})

	require.NoError(t, env.writer.WriteBootstrap(t.Context(), "", testInstance, testPayload))

	calls := env.requests.snapshot()
	require.Len(t, calls, 1)
	assert.Equal(t, string(testProject), calls[0].query["project"])
}

func TestPatchConfigRefusesEveryKeyOutsideTheAllowlist(t *testing.T) {
	t.Parallel()

	refused := []string{
		"volatile.uuid",
		"volatile.uuid.generation",
		"volatile.base_image",
		"security.privileged",
		"user.evil",
		"user.spiffe-bootstrap ",
		"",
	}

	for _, key := range refused {
		t.Run(key, func(t *testing.T) {
			t.Parallel()

			env := newTestEnv(t, func(writer http.ResponseWriter, _ *http.Request) {
				writeSyncEnvelope(t, writer)
			})

			err := env.writer.patchConfig(t.Context(), testProject, testInstance, key, "anything")
			require.Error(t, err)
			require.ErrorIs(t, err, ErrKeyNotAllowed)
			assert.Contains(t, err.Error(), strconv.Quote(key))
			assert.Empty(t, env.requests.snapshot(), "a refused key must never reach the network")
		})
	}
}

func TestWriteBootstrapRefusesAnEmptyPayload(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t, func(writer http.ResponseWriter, _ *http.Request) {
		writeSyncEnvelope(t, writer)
	})

	err := env.writer.WriteBootstrap(t.Context(), testProject, testInstance, "")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrEmptyPayload)
	assert.Empty(t, env.requests.snapshot(), "an empty payload would clear the key, so nothing is sent")
}

func TestBootstrapRefusesAnUnusableInstanceName(t *testing.T) {
	t.Parallel()

	names := map[string]attestor.InstanceName{
		"empty":            "",
		"snapshot":         "spike-guest-a/snap0",
		"traversal":        "../spire-server",
		"query injection":  "spike-guest-a?project=default",
		"escape sequence":  "spike-guest-a%2Fsnap0",
		"whitespace":       "spike guest a",
		"too long":         attestor.InstanceName(strings.Repeat("a", maxInstanceNameLength+1)),
		"non-ascii letter": "spike-guest-ä",
	}

	for name, instance := range names {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			env := newTestEnv(t, func(writer http.ResponseWriter, _ *http.Request) {
				writeSyncEnvelope(t, writer)
			})

			err := env.writer.WriteBootstrap(t.Context(), testProject, instance, testPayload)
			require.Error(t, err)
			require.ErrorIs(t, err, ErrInvalidTarget)
			assert.Empty(t, env.requests.snapshot(), "an unusable name must never reach the request path")
		})
	}
}

func TestBootstrapAuthorizationDenialIsAttemptedExactlyOnce(t *testing.T) {
	t.Parallel()

	statuses := []int{http.StatusUnauthorized, http.StatusForbidden}

	for _, status := range statuses {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			t.Parallel()

			env := newTestEnv(t, func(writer http.ResponseWriter, _ *http.Request) {
				writeErrorEnvelope(t, writer, status, "Permission denied")
			})

			err := env.writer.WriteBootstrap(t.Context(), testProject, testInstance, testPayload)
			require.Error(t, err)
			require.ErrorIs(t, err, attestor.ErrBackendUnauthorized)
			require.NotErrorIs(t, err, attestor.ErrBackendUnavailable)
			require.NotErrorIs(t, err, attestor.ErrBackendPermanent)
			assert.Contains(t, err.Error(), "Permission denied")
			assert.Len(t, env.requests.snapshot(), 1, "an authorization denial is never retried")
		})
	}
}

func TestBootstrapPermanentFailuresAreAttemptedExactlyOnce(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		handler  http.HandlerFunc
		contains string
	}{
		{
			name: "unexpected status",
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				writer.WriteHeader(http.StatusNotImplemented)
			},
			contains: "501",
		},
		{
			name: "instance not found",
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				writeErrorEnvelope(t, writer, http.StatusNotFound, "Instance not found")
			},
			contains: "Instance not found",
		},
		{
			name: "malformed body",
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", contentTypeValue)
				_, _ = writer.Write([]byte("{not json"))
			},
			contains: "decode Incus envelope",
		},
		{
			name: "error envelope behind a success status",
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				writeErrorEnvelope(t, writer, http.StatusOK, "Failed to update instance")
			},
			contains: "Failed to update instance",
		},
		{
			name: "async answer without an operation",
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				writeRawEnvelope(t, writer, http.StatusAccepted, map[string]any{
					"type":        asyncType,
					"status":      "Operation created",
					"status_code": 100,
					"operation":   "",
					"metadata":    map[string]any{},
				})
			},
			contains: "no operation id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			env := newTestEnv(t, tt.handler)

			err := env.writer.WriteBootstrap(t.Context(), testProject, testInstance, testPayload)
			require.Error(t, err)
			require.ErrorIs(t, err, attestor.ErrBackendPermanent)
			require.NotErrorIs(t, err, attestor.ErrBackendUnavailable)
			require.NotErrorIs(t, err, attestor.ErrBackendUnauthorized)
			assert.Contains(t, err.Error(), tt.contains)
			assert.Len(t, env.requests.snapshot(), 1, "a permanent failure is never retried")
		})
	}
}

func TestBootstrapRetriesATransientTransportFault(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	env := newTestEnv(t, func(writer http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == firstCall {
			hijackAndClose(t, writer)

			return
		}

		writeSyncEnvelope(t, writer)
	})

	require.NoError(t, env.writer.WriteBootstrap(t.Context(), testProject, testInstance, testPayload))
	assert.GreaterOrEqual(t, calls.Load(), retriedAtLeast)
}

func TestBootstrapStopsAtTheRetryBound(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	env := newTestEnv(t, func(writer http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		hijackAndClose(t, writer)
	})

	err := env.writer.WriteBootstrap(t.Context(), testProject, testInstance, testPayload)
	require.Error(t, err)
	require.ErrorIs(t, err, attestor.ErrBackendUnavailable)
	assert.Equal(t, int32(maxAttempts), calls.Load(), "a transient fault is attempted exactly maxAttempts times")
}

func TestBootstrapTimeoutIsBackendUnavailable(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t, func(writer http.ResponseWriter, req *http.Request) {
		select {
		case <-req.Context().Done():
		case <-time.After(blockLongerThanTimeout):
			writeSyncEnvelope(t, writer)
		}
	}, func(cfg *Config) {
		cfg.RequestTimeout = shortCallTimeout
	})

	err := env.writer.WriteBootstrap(t.Context(), testProject, testInstance, testPayload)
	require.Error(t, err)
	require.ErrorIs(t, err, attestor.ErrBackendUnavailable)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestBootstrapWaitsForAnAsyncOperation(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t, func(writer http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodPatch {
			writeAsyncEnvelope(t, writer)

			return
		}

		writeOperationEnvelope(t, writer, operationSuccess, "Success", "")
	}, func(cfg *Config) {
		cfg.RequestTimeout = waitCallTimeout
	})

	require.NoError(t, env.writer.WriteBootstrap(t.Context(), testProject, testInstance, testPayload))

	calls := env.requests.snapshot()
	require.Len(t, calls, 2, "an async answer costs the PATCH plus one bounded wait")
	assert.Equal(t, http.MethodPatch, calls[0].method)
	assert.Equal(t, http.MethodGet, calls[1].method)
	assert.Equal(t, operationPath, calls[1].path)

	waited, err := strconv.Atoi(calls[1].query["timeout"])
	require.NoError(t, err)
	assert.Positive(t, waited, "the operation wait is bounded, never indefinite")
	assert.LessOrEqual(t, waited, int(waitCallTimeout.Seconds()))
}

func TestBootstrapAsyncOperationOutcomes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		statusCode int
		status     string
		failure    string
		wantErr    error
		contains   string
	}{
		{
			name:       "failed operation is permanent",
			statusCode: operationFailure,
			status:     "Failure",
			failure:    "Failed to update instance config",
			wantErr:    attestor.ErrBackendPermanent,
			contains:   "Failed to update instance config",
		},
		{
			name:       "cancelled operation is permanent",
			statusCode: 401,
			status:     "Cancelled",
			wantErr:    attestor.ErrBackendPermanent,
			contains:   "Cancelled",
		},
		{
			name:       "operation still running after the wait is transient",
			statusCode: 103,
			status:     "Running",
			wantErr:    attestor.ErrBackendUnavailable,
			contains:   "Running",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			env := newTestEnv(t, func(writer http.ResponseWriter, req *http.Request) {
				if req.Method == http.MethodPatch {
					writeAsyncEnvelope(t, writer)

					return
				}

				writeOperationEnvelope(t, writer, tt.statusCode, tt.status, tt.failure)
			})

			err := env.writer.WriteBootstrap(t.Context(), testProject, testInstance, testPayload)
			require.Error(t, err)
			require.ErrorIs(t, err, tt.wantErr)
			assert.Contains(t, err.Error(), tt.contains)
		})
	}
}

func TestBootstrapNeverLeaksThePayloadIntoAnError(t *testing.T) {
	t.Parallel()

	echo := "Invalid config value " + testPayload + " for user.spiffe-bootstrap"

	tests := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{
			name: "error envelope echoes the payload",
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				writeErrorEnvelope(t, writer, http.StatusBadRequest, echo)
			},
		},
		{
			name: "failed operation echoes the payload",
			handler: func(writer http.ResponseWriter, req *http.Request) {
				if req.Method == http.MethodPatch {
					writeAsyncEnvelope(t, writer)

					return
				}

				writeOperationEnvelope(t, writer, operationFailure, "Failure", echo)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			env := newTestEnv(t, tt.handler)

			err := env.writer.WriteBootstrap(t.Context(), testProject, testInstance, testPayload)
			require.Error(t, err)
			assert.NotContains(t, err.Error(), testPayload, "Appendix D: a nonce value never reaches an error")
			assert.Contains(t, err.Error(), redactedMarker)
		})
	}
}

func TestNewWriterValidatesConfig(t *testing.T) {
	t.Parallel()

	files := writeClientPEMs(t)
	serverCert, err := generateSelfSignedCert()
	require.NoError(t, err)
	files.serverCert = writeFile(t, "server.crt", serverCert.certPEM)

	valid := Config{
		ServerURL:         "https://127.0.0.1:8443",
		ClientCertPEMPath: files.clientCert,
		ClientKeyPEMPath:  files.clientKey,
		ServerCertPEMPath: files.serverCert,
		DefaultProject:    testProject,
		RequestTimeout:    time.Second,
	}

	tests := []struct {
		name    string
		mutate  func(cfg Config) Config
		wantErr string
	}{
		{
			name:    "missing server URL",
			mutate:  func(cfg Config) Config { cfg.ServerURL = ""; return cfg },
			wantErr: "ServerURL is required",
		},
		{
			name:    "http is rejected",
			mutate:  func(cfg Config) Config { cfg.ServerURL = "http://127.0.0.1:8443"; return cfg },
			wantErr: "https origin",
		},
		{
			name:    "missing client certificate",
			mutate:  func(cfg Config) Config { cfg.ClientCertPEMPath = ""; return cfg },
			wantErr: "ClientCertPEMPath is required",
		},
		{
			name:    "missing client key",
			mutate:  func(cfg Config) Config { cfg.ClientKeyPEMPath = ""; return cfg },
			wantErr: "ClientKeyPEMPath is required",
		},
		{
			name:    "missing project",
			mutate:  func(cfg Config) Config { cfg.DefaultProject = ""; return cfg },
			wantErr: "DefaultProject is required",
		},
		{
			name:    "zero timeout",
			mutate:  func(cfg Config) Config { cfg.RequestTimeout = 0; return cfg },
			wantErr: "RequestTimeout must be positive",
		},
		{
			name:    "both server pins",
			mutate:  func(cfg Config) Config { cfg.ServerCertFingerprint = fingerprintOf(serverCert.cert.Raw); return cfg },
			wantErr: "exactly one of ServerCertPEMPath and ServerCertFingerprint",
		},
		{
			name:    "neither server pin",
			mutate:  func(cfg Config) Config { cfg.ServerCertPEMPath = ""; return cfg },
			wantErr: "exactly one of ServerCertPEMPath and ServerCertFingerprint",
		},
		{
			name: "malformed fingerprint",
			mutate: func(cfg Config) Config {
				cfg.ServerCertPEMPath = ""
				cfg.ServerCertFingerprint = "not-a-fingerprint"

				return cfg
			},
			wantErr: "ServerCertFingerprint must be 64 hex characters",
		},
		{
			name:    "missing client certificate file",
			mutate:  func(cfg Config) Config { cfg.ClientCertPEMPath = filepath.Join(t.TempDir(), "absent"); return cfg },
			wantErr: "stat ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := NewWriter(tt.mutate(valid))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestNewWriterAcceptsAFingerprintPin(t *testing.T) {
	t.Parallel()

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeSyncEnvelope(t, writer)
	}))
	server.StartTLS()
	t.Cleanup(server.Close)

	files := writeClientPEMs(t)
	writer, err := NewWriter(Config{
		ServerURL:             server.URL,
		ClientCertPEMPath:     files.clientCert,
		ClientKeyPEMPath:      files.clientKey,
		ServerCertFingerprint: fingerprintOf(server.Certificate().Raw),
		DefaultProject:        testProject,
		RequestTimeout:        time.Second,
	})
	require.NoError(t, err)

	require.NoError(t, writer.WriteBootstrap(t.Context(), testProject, testInstance, testPayload))
}

func TestBootstrapPinMismatchIsPermanent(t *testing.T) {
	t.Parallel()

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeSyncEnvelope(t, writer)
	}))
	server.StartTLS()
	t.Cleanup(server.Close)

	files := writeClientPEMs(t)
	writer, err := NewWriter(Config{
		ServerURL:             server.URL,
		ClientCertPEMPath:     files.clientCert,
		ClientKeyPEMPath:      files.clientKey,
		ServerCertFingerprint: strings.Repeat("a", sha256HexLength),
		DefaultProject:        testProject,
		RequestTimeout:        time.Second,
	})
	require.NoError(t, err)

	err = writer.WriteBootstrap(t.Context(), testProject, testInstance, testPayload)
	require.Error(t, err)
	require.ErrorIs(t, err, attestor.ErrBackendPermanent)
	require.NotErrorIs(t, err, attestor.ErrBackendUnavailable)
}

// record stores one observed request.
func (r *recorder) record(call capturedRequest) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.calls = append(r.calls, call)
}

// snapshot returns the requests observed so far.
func (r *recorder) snapshot() []capturedRequest {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	return append([]capturedRequest(nil), r.calls...)
}

// newTestEnv starts a TLS httptest server that speaks Incus-shaped JSON and
// records every request before handing it to handler.
func newTestEnv(t *testing.T, handler http.HandlerFunc, mutators ...func(*Config)) *testEnv {
	t.Helper()

	requests := &recorder{}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
		body, err := io.ReadAll(req.Body)
		assert.NoError(t, err)

		query := map[string]string{}
		for key, values := range req.URL.Query() {
			query[key] = values[0]
		}

		requests.record(capturedRequest{
			method:      req.Method,
			path:        req.URL.Path,
			query:       query,
			body:        string(body),
			contentType: req.Header.Get("Content-Type"),
		})

		handler(writer, req)
	}))
	server.StartTLS()
	t.Cleanup(server.Close)

	files := writeClientPEMs(t)
	files.serverCert = writeFile(t, "server.crt", pemEncode("CERTIFICATE", server.Certificate().Raw))

	cfg := Config{
		ServerURL:         server.URL,
		ClientCertPEMPath: files.clientCert,
		ClientKeyPEMPath:  files.clientKey,
		ServerCertPEMPath: files.serverCert,
		DefaultProject:    testProject,
		RequestTimeout:    time.Second,
	}
	for _, mutate := range mutators {
		mutate(&cfg)
	}

	writer, err := NewWriter(cfg)
	require.NoError(t, err)

	return &testEnv{writer: writer, requests: requests, files: files}
}

// writeSyncEnvelope writes the empty sync answer Incus gives an instance PATCH.
func writeSyncEnvelope(t *testing.T, writer http.ResponseWriter) {
	t.Helper()

	writeRawEnvelope(t, writer, http.StatusOK, map[string]any{
		"type":        "sync",
		"status":      "Success",
		"status_code": http.StatusOK,
		"operation":   "",
		"error_code":  0,
		"error":       "",
		"metadata":    map[string]any{},
	})
}

// writeAsyncEnvelope writes the operation-shaped answer a background update
// would produce.
func writeAsyncEnvelope(t *testing.T, writer http.ResponseWriter) {
	t.Helper()

	writeRawEnvelope(t, writer, http.StatusAccepted, map[string]any{
		"type":        asyncType,
		"status":      "Operation created",
		"status_code": 100,
		"operation":   operationURL,
		"error_code":  0,
		"error":       "",
		"metadata": map[string]any{
			"id":          testOperationID,
			"class":       "task",
			"description": "Updating instance",
			"status":      "Running",
			"status_code": 103,
			"err":         "",
		},
	})
}

// writeOperationEnvelope writes the sync envelope returned by an operation wait.
func writeOperationEnvelope(t *testing.T, writer http.ResponseWriter, statusCode int, status string, failure string) {
	t.Helper()

	writeRawEnvelope(t, writer, http.StatusOK, map[string]any{
		"type":        "sync",
		"status":      "Success",
		"status_code": http.StatusOK,
		"operation":   "",
		"error_code":  0,
		"error":       "",
		"metadata": map[string]any{
			"id":          testOperationID,
			"class":       "task",
			"description": "Updating instance",
			"status":      status,
			"status_code": statusCode,
			"err":         failure,
		},
	})
}

// writeErrorEnvelope writes the Incus error envelope for status.
func writeErrorEnvelope(t *testing.T, writer http.ResponseWriter, status int, message string) {
	t.Helper()

	writeRawEnvelope(t, writer, status, map[string]any{
		"type":        "error",
		"status":      "",
		"status_code": 0,
		"error_code":  status,
		"error":       message,
		"metadata":    nil,
	})
}

// writeRawEnvelope writes body as the JSON response for status.
func writeRawEnvelope(t *testing.T, writer http.ResponseWriter, status int, body map[string]any) {
	t.Helper()

	encoded, err := json.Marshal(body)
	require.NoError(t, err)

	writer.Header().Set("Content-Type", contentTypeValue)
	writer.WriteHeader(status)
	_, err = writer.Write(encoded)
	require.NoError(t, err)
}

// hijackAndClose drops the connection mid-response to produce a transient
// transport fault.
func hijackAndClose(t *testing.T, writer http.ResponseWriter) {
	t.Helper()

	hijacker, ok := writer.(http.Hijacker)
	require.True(t, ok)

	conn, _, err := hijacker.Hijack()
	require.NoError(t, err)
	require.NoError(t, conn.Close())
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
		Subject:               pkix.Name{CommonName: "bootstrap-writer-test"},
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

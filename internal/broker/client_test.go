package broker

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	brokerv1 "github.com/spiffe/go-spiffe/v2/exp/proto/spiffe/broker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/anypb"

	incusv1alpha1 "github.com/componere/incusos-spire/proto/componere/incus/v1alpha1"
)

const (
	// incusReferenceTypeURL is the frozen reference type URL from P6. The broker
	// allowlist and the plugin must agree on it exactly.
	incusReferenceTypeURL = "type.googleapis.com/componere.incus.v1alpha1.IncusInstanceReference"
	// bufferSize is the in-process listener buffer.
	bufferSize = 1 << 20
	// testTimeout is the request timeout used by tests that expect to succeed.
	testTimeout = 5 * time.Second
	// shortTimeout is the request timeout used by tests that expect to expire.
	shortTimeout = 50 * time.Millisecond
	// waitTimeout bounds how long a test waits for a server-side observation.
	waitTimeout = 2 * time.Second
	// allowlistDenialMessage is the PermissionDenied message SPIRE 1.15.2
	// returned live when the broker's SPIFFE ID was not allowed to use the
	// submitted reference type.
	allowlistDenialMessage = `broker "spiffe://spike.incus.internal/incus-broker" is not allowed ` +
		`to use reference type "type.googleapis.com/componere.incus.v1alpha1.IncusInstanceReference"`
	// pluginDenialMessage is the PermissionDenied message the Incus workload
	// attestor returns after it has attested the reference and its own policy
	// rejected the instance. Same status code, entirely different cause.
	pluginDenialMessage = "incus instance reference is not attestable"
	// backendAuthFailureMessage is the FailedPrecondition message the Incus
	// workload attestor returns when Incus refused its credential.
	backendAuthFailureMessage = "incus backend authorization failed"
)

// respondFunc produces the outcome of one SubscribeToX509SVID call. attempt is
// the zero-based call ordinal, so a script can fail early calls and satisfy a
// later one.
type respondFunc func(
	attempt int,
	stream grpc.ServerStreamingServer[brokerv1.SubscribeToX509SVIDResponse],
) error

// stubAPI is a test double for the experimental Broker API server. It records
// what the client sent and replays a scripted outcome.
type stubAPI struct {
	brokerv1.UnimplementedAPIServer

	// respond produces the outcome of each call.
	respond respondFunc
	// mu guards the recorded call state.
	mu sync.Mutex
	// requests records every request received, in call order.
	requests []*brokerv1.SubscribeToX509SVIDRequest
	// headers records the incoming metadata of every call, in call order.
	headers []metadata.MD
}

// SubscribeToX509SVID records the call and delegates to the script.
func (stub *stubAPI) SubscribeToX509SVID(
	request *brokerv1.SubscribeToX509SVIDRequest,
	stream grpc.ServerStreamingServer[brokerv1.SubscribeToX509SVIDResponse],
) error {
	incoming, _ := metadata.FromIncomingContext(stream.Context())

	stub.mu.Lock()
	attempt := len(stub.requests)
	stub.requests = append(stub.requests, request)
	stub.headers = append(stub.headers, incoming)
	stub.mu.Unlock()

	return stub.respond(attempt, stream)
}

// recorded returns copies of the recorded requests and metadata.
func (stub *stubAPI) recorded() ([]*brokerv1.SubscribeToX509SVIDRequest, []metadata.MD) {
	stub.mu.Lock()
	defer stub.mu.Unlock()

	return append([]*brokerv1.SubscribeToX509SVIDRequest(nil), stub.requests...),
		append([]metadata.MD(nil), stub.headers...)
}

func TestFetchX509SVIDNestsTheReferenceTwice(t *testing.T) {
	reference := incusReference(t)
	stub := &stubAPI{respond: sendSVID(testSVID())}
	client := newTestClient(t, testTimeout, stub)

	svid, err := client.FetchX509SVID(context.Background(), reference)
	require.NoError(t, err)

	requests, _ := stub.recorded()
	require.Len(t, requests, 1)

	workloadReference := requests[0].GetReference()
	require.NotNil(t, workloadReference, "the Any must be wrapped in a WorkloadReference")

	inner := workloadReference.GetReference()
	require.NotNil(t, inner, "WorkloadReference.reference must carry the Any")
	assert.Equal(t, incusReferenceTypeURL, inner.GetTypeUrl())
	assert.Equal(t, reference.GetValue(), inner.GetValue())

	assert.Equal(t, SPIFFEID("spiffe://spike.incus.internal/guest"), svid.ID)
	assert.Equal(t, []byte("chain-der"), svid.ChainDER)
	assert.Equal(t, []byte("key-der"), svid.KeyDER)
	assert.Equal(t, []byte("bundle-der"), svid.BundleDER)
	assert.Equal(t, "internal", svid.Hint)

	require.NoError(t, client.Close(), "closing a caller-owned client must succeed")
}

func TestFetchX509SVIDSendsTheMandatorySecurityHeader(t *testing.T) {
	stub := &stubAPI{respond: sendSVID(testSVID())}
	client := newTestClient(t, testTimeout, stub)

	// A caller that already set the header, wrongly, must not be able to defeat
	// or duplicate it: SPIRE rejects a repeated value as harshly as a missing one.
	ctx := metadata.AppendToOutgoingContext(context.Background(), securityHeaderKey, "false")

	_, err := client.FetchX509SVID(ctx, incusReference(t))
	require.NoError(t, err)

	_, headers := stub.recorded()
	require.Len(t, headers, 1)

	values := headers[0].Get(securityHeaderKey)
	require.Len(t, values, 1, "SPIRE requires exactly one broker.spiffe.io value")
	assert.Equal(t, securityHeaderValue, values[0])
}

func TestFetchX509SVIDMapsStatusCodesToSentinels(t *testing.T) {
	tests := []struct {
		name string
		// respond scripts the stub's answer.
		respond respondFunc
		// want is the sentinel the error must match, or nil when no sentinel
		// may match.
		want error
		// notWant is a sentinel the error must not match, so an over-claiming
		// classification is caught.
		notWant error
		code    codes.Code
	}{
		{
			name:    "missing security header",
			respond: failWith(codes.InvalidArgument, "security header missing from request"),
			want:    ErrInvalidRequest,
			code:    codes.InvalidArgument,
		},
		{
			name:    "reference type outside the broker allowlist",
			respond: failWith(codes.PermissionDenied, allowlistDenialMessage),
			want:    ErrReferenceTypeDenied,
			code:    codes.PermissionDenied,
		},
		{
			name:    "attestor denied the reference after attesting it",
			respond: failWith(codes.PermissionDenied, pluginDenialMessage),
			want:    ErrPermissionDenied,
			notWant: ErrReferenceTypeDenied,
			code:    codes.PermissionDenied,
		},
		{
			name:    "plugin reported a backend authorization failure",
			respond: failWith(codes.FailedPrecondition, backendAuthFailureMessage),
			want:    nil,
			code:    codes.FailedPrecondition,
		},
		{
			name:    "broker socket not accepting connections",
			respond: failWith(codes.Unavailable, "connection refused"),
			want:    ErrTransport,
			code:    codes.Unavailable,
		},
		{
			name:    "no usable TLS peer identity",
			respond: failWith(codes.Unauthenticated, "unable to get caller identity"),
			want:    ErrTransport,
			code:    codes.Unauthenticated,
		},
		{
			name:    "server side deadline exceeded",
			respond: failWith(codes.DeadlineExceeded, "context deadline exceeded"),
			want:    ErrTimeout,
			code:    codes.DeadlineExceeded,
		},
		{
			name:    "no attestor handled the reference",
			respond: failWith(codes.Unimplemented, "no workload attestor handled reference"),
			want:    nil,
			code:    codes.Unimplemented,
		},
		{
			name:    "response carried an empty SVID list",
			respond: sendResponse(&brokerv1.SubscribeToX509SVIDResponse{}),
			want:    ErrNoSVID,
			code:    codes.Unknown,
		},
		{
			name:    "stream ended before an SVID arrived",
			respond: closeStream,
			want:    ErrNoSVID,
			code:    codes.Unknown,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := newTestClient(t, testTimeout, &stubAPI{respond: test.respond})

			_, err := client.FetchX509SVID(context.Background(), incusReference(t))
			require.Error(t, err)

			if test.want == nil {
				assertNoSentinel(t, err)
			} else {
				require.ErrorIs(t, err, test.want)
			}
			if test.notWant != nil {
				require.NotErrorIs(t, err, test.notWant)
			}

			assert.Equal(t, test.code, status.Code(err), "the gRPC status must stay in the chain")
		})
	}
}

func TestFetchX509SVIDRetriesOnlyTransientTransportFailures(t *testing.T) {
	tests := []struct {
		name    string
		respond respondFunc
		// wantErr is the sentinel the failure must match. Nil with an empty
		// wantErrText means the call must succeed.
		wantErr error
		// wantErrText is asserted for a failure this package deliberately
		// leaves unmapped, which must still not be retried.
		wantErrText  string
		wantAttempts int
	}{
		{
			name: "unavailable transport is retried until it succeeds",
			respond: func(
				attempt int,
				stream grpc.ServerStreamingServer[brokerv1.SubscribeToX509SVIDResponse],
			) error {
				if attempt < maxAttempts-1 {
					return status.Error(codes.Unavailable, "connection refused")
				}

				return sendSVID(testSVID())(attempt, stream)
			},
			wantErr:      nil,
			wantAttempts: maxAttempts,
		},
		{
			name:         "unavailable transport is retried a bounded number of times",
			respond:      failWith(codes.Unavailable, "connection refused"),
			wantErr:      ErrTransport,
			wantAttempts: maxAttempts,
		},
		{
			name:         "allowlist denial is never retried",
			respond:      failWith(codes.PermissionDenied, allowlistDenialMessage),
			wantErr:      ErrReferenceTypeDenied,
			wantAttempts: 1,
		},
		{
			name:         "post-attestation denial is never retried",
			respond:      failWith(codes.PermissionDenied, pluginDenialMessage),
			wantErr:      ErrPermissionDenied,
			wantAttempts: 1,
		},
		{
			name:         "plugin backend authorization failure is never retried",
			respond:      failWith(codes.FailedPrecondition, backendAuthFailureMessage),
			wantErr:      nil,
			wantErrText:  backendAuthFailureMessage,
			wantAttempts: 1,
		},
		{
			name:         "invalid argument is never retried",
			respond:      failWith(codes.InvalidArgument, "security header missing from request"),
			wantErr:      ErrInvalidRequest,
			wantAttempts: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stub := &stubAPI{respond: test.respond}
			client := newTestClient(t, testTimeout, stub)

			_, err := client.FetchX509SVID(context.Background(), incusReference(t))
			switch {
			case test.wantErr != nil:
				require.ErrorIs(t, err, test.wantErr)
			case test.wantErrText != "":
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.wantErrText)
				assertNoSentinel(t, err)
			default:
				require.NoError(t, err)
			}

			requests, _ := stub.recorded()
			assert.Len(t, requests, test.wantAttempts)
		})
	}
}

func TestFetchX509SVIDRejectsAReferenceWithoutATypeURL(t *testing.T) {
	tests := []struct {
		name      string
		reference *anypb.Any
	}{
		{name: "nil reference", reference: nil},
		{name: "empty reference", reference: &anypb.Any{}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stub := &stubAPI{respond: sendSVID(testSVID())}
			client := newTestClient(t, testTimeout, stub)

			_, err := client.FetchX509SVID(context.Background(), test.reference)
			require.ErrorIs(t, err, ErrInvalidRequest)

			requests, _ := stub.recorded()
			assert.Empty(t, requests, "an unusable reference must never reach the endpoint")
		})
	}
}

func TestFetchX509SVIDTimesOutWhenNoSVIDArrives(t *testing.T) {
	stub := &stubAPI{respond: blockUntilDone(nil)}
	client := newTestClient(t, shortTimeout, stub)

	_, err := client.FetchX509SVID(context.Background(), incusReference(t))
	require.ErrorIs(t, err, ErrTimeout)
}

func TestFetchX509SVIDClosesTheStreamAfterTheFirstSVID(t *testing.T) {
	closed := make(chan struct{})
	stub := &stubAPI{respond: blockUntilDone(closed)}
	client := newTestClient(t, testTimeout, stub)

	svid, err := client.FetchX509SVID(context.Background(), incusReference(t))
	require.NoError(t, err)
	assert.Equal(t, SPIFFEID("spiffe://spike.incus.internal/guest"), svid.ID)

	select {
	case <-closed:
	case <-time.After(waitTimeout):
		t.Fatal("the server-streaming call stayed open after the first SVID")
	}
}

func TestNewClientRejectsAnInvalidConfig(t *testing.T) {
	valid := Config{
		BrokerSocketPath:      "/run/spire/broker-sockets/broker.sock",
		WorkloadAPISocketPath: "/run/spire/agent-sockets/api.sock",
		AgentID:               "spiffe://spike.incus.internal/incus-broker",
		AgentTrustDomain:      "",
		RequestTimeout:        testTimeout,
	}

	tests := []struct {
		name    string
		mutate  func(cfg *Config)
		wantErr string
	}{
		{
			name:    "missing broker socket",
			mutate:  func(cfg *Config) { cfg.BrokerSocketPath = "" },
			wantErr: "BrokerSocketPath is required",
		},
		{
			name:    "relative broker socket",
			mutate:  func(cfg *Config) { cfg.BrokerSocketPath = "broker.sock" },
			wantErr: "BrokerSocketPath must be an absolute path",
		},
		{
			name:    "missing workload api socket",
			mutate:  func(cfg *Config) { cfg.WorkloadAPISocketPath = "" },
			wantErr: "WorkloadAPISocketPath is required",
		},
		{
			name:    "no endpoint authorization",
			mutate:  func(cfg *Config) { cfg.AgentID = "" },
			wantErr: "exactly one of AgentID and AgentTrustDomain is required",
		},
		{
			name:    "ambiguous endpoint authorization",
			mutate:  func(cfg *Config) { cfg.AgentTrustDomain = "spike.incus.internal" },
			wantErr: "exactly one of AgentID and AgentTrustDomain is required",
		},
		{
			name:    "non positive timeout",
			mutate:  func(cfg *Config) { cfg.RequestTimeout = 0 },
			wantErr: "RequestTimeout must be positive",
		},
		{
			name:    "unparseable agent id",
			mutate:  func(cfg *Config) { cfg.AgentID = "incus-broker" },
			wantErr: "parse AgentID",
		},
		{
			name: "unparseable trust domain",
			mutate: func(cfg *Config) {
				cfg.AgentID = ""
				cfg.AgentTrustDomain = "spiffe://not a domain"
			},
			wantErr: "parse AgentTrustDomain",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := valid
			test.mutate(&cfg)

			client, err := NewClient(context.Background(), cfg)
			require.Error(t, err)
			assert.Nil(t, client)
			assert.Contains(t, err.Error(), test.wantErr)
		})
	}
}

// newTestClient starts an in-process Broker API server backed by stub and
// returns a Client that reaches it through the production dial interceptors, so
// the mandatory header travels the same path it does in production.
func newTestClient(t *testing.T, timeout time.Duration, stub *stubAPI) *Client {
	t.Helper()

	listener := bufconn.Listen(bufferSize)
	server := grpc.NewServer()
	brokerv1.RegisterAPIServer(server, stub)

	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = server.Serve(listener)
	}()

	options := securityHeaderDialOptions()
	options = append(options,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return listener.DialContext(ctx)
		}),
	)

	conn, err := grpc.NewClient("passthrough:///bufnet", options...)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = conn.Close()
		server.Stop()
		<-served
	})

	return newClient(brokerv1.NewAPIClient(conn), timeout)
}

// incusReference builds the Any the P7 harness sends, using the frozen P6
// message so the test proves the real type URL survives the nesting.
func incusReference(t *testing.T) *anypb.Any {
	t.Helper()

	reference, err := anypb.New(&incusv1alpha1.IncusInstanceReference{
		InstanceUuid:   "e9e6a2a0-d695-42d3-8e8c-92d290bfc7da",
		Project:        "spike-spiffe",
		GenerationUuid: "74957ed8-19bc-4d23-b76b-763bb6f8bb60",
		Server:         "822b00ed474a2574d43223cbf34919b76a64946e145ec246aa4ae2e43318afdd",
	})
	require.NoError(t, err)

	return reference
}

// testSVID is the SVID the stub delivers on the positive path.
func testSVID() *brokerv1.X509SVID {
	return &brokerv1.X509SVID{
		SpiffeId:    "spiffe://spike.incus.internal/guest",
		X509Svid:    []byte("chain-der"),
		X509SvidKey: []byte("key-der"),
		Bundle:      []byte("bundle-der"),
		Hint:        "internal",
	}
}

// sendSVID scripts a stub that delivers svid once and returns.
func sendSVID(svid *brokerv1.X509SVID) respondFunc {
	return sendResponse(&brokerv1.SubscribeToX509SVIDResponse{
		Svids: []*brokerv1.X509SVID{svid},
	})
}

// sendResponse scripts a stub that sends response once and returns.
func sendResponse(response *brokerv1.SubscribeToX509SVIDResponse) respondFunc {
	return func(
		_ int,
		stream grpc.ServerStreamingServer[brokerv1.SubscribeToX509SVIDResponse],
	) error {
		return stream.Send(response)
	}
}

// failWith scripts a stub that always answers with a gRPC status.
func failWith(code codes.Code, message string) respondFunc {
	return func(_ int, _ grpc.ServerStreamingServer[brokerv1.SubscribeToX509SVIDResponse]) error {
		return status.Error(code, message)
	}
}

// closeStream scripts a stub that ends the stream cleanly without sending.
func closeStream(_ int, _ grpc.ServerStreamingServer[brokerv1.SubscribeToX509SVIDResponse]) error {
	return nil
}

// blockUntilDone scripts a stub that holds the stream open until the client
// cancels it. When closed is non-nil the stub first delivers one SVID and then
// closes closed once the stream context ends, which turns the script into a
// probe for client-side stream shutdown.
func blockUntilDone(closed chan struct{}) respondFunc {
	return func(
		_ int,
		stream grpc.ServerStreamingServer[brokerv1.SubscribeToX509SVIDResponse],
	) error {
		if closed != nil {
			if err := stream.Send(&brokerv1.SubscribeToX509SVIDResponse{
				Svids: []*brokerv1.X509SVID{testSVID()},
			}); err != nil {
				return err
			}
		}

		<-stream.Context().Done()
		if closed != nil {
			close(closed)
		}

		return stream.Context().Err()
	}
}

// assertNoSentinel fails when err matches a sentinel this package documents, so
// an unmapped status code cannot be mistaken for a handled outcome.
func assertNoSentinel(t *testing.T, err error) {
	t.Helper()

	for _, sentinel := range []error{
		ErrInvalidRequest,
		ErrPermissionDenied,
		ErrReferenceTypeDenied,
		ErrTransport,
		ErrTimeout,
		ErrNoSVID,
	} {
		assert.NotErrorIs(t, err, sentinel, "unexpected sentinel %v", sentinel)
	}
}

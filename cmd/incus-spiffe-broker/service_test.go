package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/componere/incusos-spire/internal/attestor"
	attestormocks "github.com/componere/incusos-spire/internal/attestor/mocks"
	"github.com/componere/incusos-spire/internal/broker"
	"github.com/componere/incusos-spire/internal/nonce"
	"github.com/componere/incusos-spire/internal/nonce/memory"
	noncemocks "github.com/componere/incusos-spire/internal/nonce/mocks"
	incusv1alpha1 "github.com/componere/incusos-spire/proto/componere/incus/v1alpha1"
)

const (
	// guestUUID is the volatile.uuid of the instance under test.
	guestUUID attestor.InstanceUUID = "6f2c1a54-6a1e-4a2b-9f3e-0c1d2e3f4a5b"
	// otherUUID is the volatile.uuid a hostile caller claims.
	otherUUID attestor.InstanceUUID = "11112222-3333-4444-5555-666677778888"
	// guestGeneration is the volatile.uuid.generation of the instance under test.
	guestGeneration attestor.GenerationUUID = "aaaabbbb-cccc-dddd-eeee-ffff00001111"
	// guestName is the live instance name the read path resolves.
	guestName attestor.InstanceName = "spike-guest-a"
	// guestProject is the Incus project of the instance under test.
	guestProject attestor.ProjectName = "spike-spiffe"
	// knownSecret is the nonce material of a seeded record.
	knownSecret = "3f1c9b0d7e5a4c2b8d6f0a1e2c3b4d5e"
	// mintToken is the operator bearer token the fixture accepts. It is as long
	// as a real one, so no test passes because the floor was ignored.
	mintToken = "4d2f8b1c6a0e7d3f9b5c2a8e1d4f7b0c"
	// wrongToken is the same length as [mintToken] and not equal to it.
	wrongToken = "0000000000000000000000000000000f"
	// testMaxNonceTTL is the longest lifetime the fixture grants a mint request.
	testMaxNonceTTL = 10 * time.Minute
	// testCompensationTimeout bounds a detached withdrawal in the fixture.
	testCompensationTimeout = 5 * time.Second
	// testBrokerSocket is the host agent Broker API socket the fixture configures.
	testBrokerSocket = "/spike/broker-run/broker.sock"
	// testWorkloadAPISocket is the host agent Workload API socket the fixture
	// configures. SPIRE requires it to live outside the broker socket's
	// directory, and this pair does.
	testWorkloadAPISocket = "/spike/run/api.sock"
	// testAgentSPIFFEID is the host agent identity the Broker endpoint must
	// present.
	testAgentSPIFFEID = "spiffe://spike.incus.internal/spire/agent/tpm_devid/fee6de97"
	// testTrustDomain is the spike trust domain.
	testTrustDomain = "spike.incus.internal"
	// exchangeSPIFFEID is the exchange identity P9 fixes: the x509pop
	// svid_prefix "/spire-exchange" plus the plugin name and the instance UUID.
	// SPIRE's default agent_path_template turns it into
	// spiffe://spike.incus.internal/spire/agent/x509pop/incus/<uuid>.
	exchangeSPIFFEID broker.SPIFFEID = "spiffe://" + testTrustDomain +
		"/spire-exchange/incus/" + broker.SPIFFEID(guestUUID)
	// exchangeLifetime is how long the fixture's exchange leaf stays valid. It is
	// short because the material is used once, immediately, to attest.
	exchangeLifetime = 5 * time.Minute
)

// liveRecord is the instance record the read path resolves for [guestUUID].
func liveRecord() attestor.InstanceRecord {
	return attestor.InstanceRecord{
		UUID:       guestUUID,
		Generation: guestGeneration,
		Project:    guestProject,
		Type:       attestor.InstanceTypeVirtualMachine,
		Status:     attestor.InstanceStatusRunning,
		Location:   "none",
		Image:      "4a1d0f6b7c8e9a0b1c2d3e4f5a6b7c8d",
		Name:       guestName,
		CreatedAt:  "2026-08-16T09:00:00Z",
	}
}

// stubExchange is a scripted [exchangeIssuer]. It exists so the redemption path
// can be tested without the experimental Broker proto leaving
// github.com/componere/incusos-spire/internal/broker: the test injects this
// package's own port, exactly as main injects the real adapter.
type stubExchange struct {
	// svid is the SVID returned when err is nil.
	svid broker.X509SVID
	// err is the Broker failure to return instead of an SVID.
	err error
	// references records every reference the service submitted, in order.
	references []*anypb.Any
	// observe, when set, runs at fetch time. A test uses it to record where the
	// Broker call fell relative to the other collaborators.
	observe func()
}

// FetchX509SVID records the submitted reference and returns the scripted answer.
func (s *stubExchange) FetchX509SVID(_ context.Context, reference *anypb.Any) (broker.X509SVID, error) {
	s.references = append(s.references, reference)

	if s.observe != nil {
		s.observe()
	}

	if s.err != nil {
		return broker.X509SVID{}, s.err
	}

	return s.svid, nil
}

// fixture is one wired service plus the doubles behind it.
type fixture struct {
	// reader is the read-only Incus path.
	reader *attestormocks.MockInstanceReader
	// writer is the bootstrap configuration writer.
	writer *noncemocks.MockBootstrapWriter
	// exchange is the Broker API port.
	exchange *stubExchange
	// store is the nonce store the minter and the service share.
	store nonce.Store
	// service is the subject under test.
	service *Service
	// logs captures everything the service logged.
	logs *bytes.Buffer
	// leaf is the exchange certificate the stub delivers, kept so a test can
	// compare what the guest received against what was issued.
	leaf *x509.Certificate
	// signer is the private key of leaf, for the same reason.
	signer *ecdsa.PrivateKey
}

// newFixture wires a service over store with mocked Incus adapters, a scripted
// Broker API port, and the real nonce lifecycle and selector cores. The cores are
// real on purpose: the contract under test is the composition, not a restatement
// of it.
func newFixture(t *testing.T, store nonce.Store) *fixture {
	t.Helper()

	reader := attestormocks.NewMockInstanceReader(t)
	writer := noncemocks.NewMockBootstrapWriter(t)
	logs := &bytes.Buffer{}
	svid, leaf, signer := newExchangeSVID(t)
	exchange := &stubExchange{svid: svid, err: nil, references: nil, observe: nil}

	service, err := NewService(ServiceConfig{
		Reader:              reader,
		Bindings:            store,
		Minter:              nonce.NewMinter(store, writer, nonce.WithTTL(time.Minute)),
		Deriver:             attestor.NewDeriver(reader),
		Exchange:            exchange,
		Logger:              slog.New(slog.NewTextHandler(logs, nil)),
		MintTokenDigest:     sha256.Sum256([]byte(mintToken)),
		MaxNonceTTL:         testMaxNonceTTL,
		CompensationTimeout: testCompensationTimeout,
	})
	require.NoError(t, err)

	return &fixture{
		reader:   reader,
		writer:   writer,
		exchange: exchange,
		store:    store,
		service:  service,
		logs:     logs,
		leaf:     leaf,
		signer:   signer,
	}
}

// newExchangeSVID builds the SVID the Broker API stub delivers: a self-signed
// leaf whose only SAN is [exchangeSPIFFEID], its PKCS#8 key, and a bundle. It is
// self-signed because nothing under test verifies the chain; the guest agent and
// the SPIRE server do that, and P9's live run is what proves it.
func newExchangeSVID(t *testing.T) (broker.X509SVID, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	uri, err := url.Parse(string(exchangeSPIFFEID))
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Minute).Truncate(time.Second),
		NotAfter:     time.Now().Add(exchangeLifetime).Truncate(time.Second),
		URIs:         []*url.URL{uri},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	require.NoError(t, err)

	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	keyDER, err := x509.MarshalPKCS8PrivateKey(signer)
	require.NoError(t, err)

	return broker.X509SVID{
		ID:        exchangeSPIFFEID,
		ChainDER:  der,
		KeyDER:    keyDER,
		BundleDER: der,
		Hint:      "",
	}, leaf, signer
}

// post sends one JSON body to path and returns the recorded answer.
func (f *fixture) post(t *testing.T, path string, body string) *httptest.ResponseRecorder {
	t.Helper()

	return f.do(t, http.MethodPost, path, body)
}

// do sends one request with an arbitrary method, presenting the operator bearer
// token. The redeem path ignores it; the mint path requires it.
func (f *fixture) do(t *testing.T, method string, path string, body string) *httptest.ResponseRecorder {
	t.Helper()

	return f.doAs(t, method, path, body, bearerScheme+" "+mintToken)
}

// doAs sends one request presenting authorization verbatim. An empty
// authorization sends no header at all, which is how an operator who never
// configured a token reaches this service.
func (f *fixture) doAs(
	t *testing.T,
	method string,
	path string,
	body string,
	authorization string,
) *httptest.ResponseRecorder {
	t.Helper()

	request := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
	if authorization != "" {
		request.Header.Set(headerAuthorization, authorization)
	}

	recorder := httptest.NewRecorder()
	f.service.Handler().ServeHTTP(recorder, request)

	return recorder
}

// expectWrite accepts the bootstrap write for the resolved instance and returns
// a pointer that receives the written payload, which is the document a guest
// reads out of its configuration key.
func (f *fixture) expectWrite(t *testing.T) *string {
	t.Helper()

	payload := new(string)
	f.writer.EXPECT().
		WriteBootstrap(mock.Anything, guestProject, guestName, mock.Anything).
		RunAndReturn(func(_ context.Context, _ attestor.ProjectName, _ attestor.InstanceName, written string) error {
			*payload = written

			return nil
		})

	return payload
}

// mint drives the operator endpoint and returns the nonce ID and the secret,
// read the way a guest reads them: out of the payload written to the instance
// configuration key. The secret never leaves the payload through this package,
// so no test needs [nonce.Secret.Reveal].
func (f *fixture) mint(t *testing.T) (nonce.NonceID, string) {
	t.Helper()

	payload := f.expectWrite(t)

	response := f.post(t, mintPath, `{"instance_uuid":"`+string(guestUUID)+`","project":"`+string(guestProject)+`"}`)
	require.Equal(t, http.StatusCreated, response.Code, response.Body.String())

	var minted mintResponse
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &minted))

	return minted.NonceID, secretFromPayload(t, *payload)
}

// secretFromPayload extracts the nonce secret from a bootstrap payload exactly
// as a guest would after reading user.spiffe-bootstrap.
func secretFromPayload(t *testing.T, payload string) string {
	t.Helper()

	var document struct {
		Nonce             string `json:"nonce"`
		NonceID           string `json:"nonce_id"`
		BrokerURL         string `json:"broker_url"`
		BrokerFingerprint string `json:"broker_fingerprint"`
	}

	require.NoError(t, json.Unmarshal([]byte(payload), &document))
	require.NotEmpty(t, document.Nonce)

	return document.Nonce
}

// nonceIDFromPayload extracts the public nonce identifier from a bootstrap
// payload, which is how a test learns the ID of a mint whose operator answer
// never arrived.
func nonceIDFromPayload(t *testing.T, payload string) nonce.NonceID {
	t.Helper()

	var document struct {
		NonceID string `json:"nonce_id"`
	}

	require.NoError(t, json.Unmarshal([]byte(payload), &document))
	require.NotEmpty(t, document.NonceID)

	return nonce.NonceID(document.NonceID)
}

// seed stores one record directly, which is how a test arranges a lifecycle
// state that minting cannot produce, such as an expired or consumed nonce.
func seed(t *testing.T, store nonce.Store, record nonce.Record) {
	t.Helper()

	require.NoError(t, store.Put(t.Context(), record))
}

// boundRecord is a stored nonce bound to [guestUUID] and [knownSecret].
func boundRecord(id nonce.NonceID, expiresAt time.Time, used bool) nonce.Record {
	return nonce.Record{
		ID:         id,
		Hash:       nonce.HashSecret(nonce.NewSecret(knownSecret)),
		Instance:   guestUUID,
		Generation: guestGeneration,
		Project:    guestProject,
		ExpiresAt:  expiresAt,
		Used:       used,
	}
}

// redeemBody is a guest presentation of id and secret.
func redeemBody(id nonce.NonceID, secret string) string {
	return `{"nonce_id":"` + string(id) + `","nonce":"` + secret + `"}`
}

// guestAnswer is a redemption answer as the guest parses it off the wire. It is
// declared here rather than reusing [redeemResponse] on purpose: the exchange key
// is a PEM string in JSON and an [exchangeKeyPEM] in Go, and the type that
// refuses to print itself must not gain a way to be reconstructed just so a test
// can read it.
type guestAnswer struct {
	// NonceID echoes the consumed nonce.
	NonceID nonce.NonceID `json:"nonce_id"`
	// InstanceUUID is the bound volatile.uuid.
	InstanceUUID attestor.InstanceUUID `json:"instance_uuid"`
	// InstanceName is the live instance name.
	InstanceName attestor.InstanceName `json:"instance_name"`
	// Generation is the bound generation.
	Generation attestor.GenerationUUID `json:"generation"`
	// Project is the bound project.
	Project attestor.ProjectName `json:"project"`
	// Selectors are the frozen incus: selectors.
	Selectors []attestor.Selector `json:"selectors"`
	// ExchangeSPIFFEID is the exchange identity.
	ExchangeSPIFFEID broker.SPIFFEID `json:"exchange_spiffe_id"`
	// ExchangeCertChainPEM is the exchange certificate chain.
	ExchangeCertChainPEM string `json:"exchange_cert_chain_pem"`
	// ExchangeKeyPEM is the exchange private key, which is why a guest writes
	// this document to tmpfs and nowhere else.
	ExchangeKeyPEM string `json:"exchange_key_pem"`
	// ExchangeBundlePEM is the trust bundle.
	ExchangeBundlePEM string `json:"exchange_bundle_pem"`
	// ExchangeExpiresAt is the leaf's NotAfter.
	ExchangeExpiresAt time.Time `json:"exchange_expires_at"`
}

// guestAnswerOf decodes one redemption answer.
func guestAnswerOf(t *testing.T, body []byte) guestAnswer {
	t.Helper()

	var parsed guestAnswer
	require.NoError(t, json.Unmarshal(body, &parsed))

	return parsed
}

func TestMintResolvesLiveNameAndWithholdsTheSecret(t *testing.T) {
	fixture := newFixture(t, memory.New())
	fixture.reader.EXPECT().
		ReadInstanceByUUID(mock.Anything, guestUUID, guestProject).
		Return(liveRecord(), nil).
		Once()

	payload := fixture.expectWrite(t)

	response := fixture.post(t, mintPath,
		`{"instance_uuid":"`+string(guestUUID)+`","project":"`+string(guestProject)+`"}`)

	require.Equal(t, http.StatusCreated, response.Code, response.Body.String())
	require.Equal(t, []string{contentTypeJSON}, response.Header().Values("Content-Type"))

	secret := secretFromPayload(t, *payload)

	// The write landed on the name the read path resolved, which is the only
	// way the writer could have learned it: the writer credential cannot read.
	fixture.writer.AssertCalled(t, "WriteBootstrap", mock.Anything, guestProject, guestName, *payload)

	body := response.Body.String()
	require.NotContains(t, body, secret)
	require.NotContains(t, fixture.logs.String(), secret)

	var fields map[string]any
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &fields))

	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}

	require.ElementsMatch(t,
		[]string{"nonce_id", "expires_at", "instance_uuid", "instance_name", "generation", "project"},
		keys,
		"the operator answer carries no field that could hold secret material")

	var minted mintResponse
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &minted))
	require.NotEmpty(t, minted.NonceID)
	require.Equal(t, guestName, minted.InstanceName)
	require.Equal(t, guestUUID, minted.InstanceUUID)
	require.Equal(t, guestGeneration, minted.Generation)
	require.Equal(t, guestProject, minted.Project)
	require.False(t, minted.ExpiresAt.IsZero())
}

func TestRedeemNeverTrustsACallerSuppliedInstanceUUID(t *testing.T) {
	fixture := newFixture(t, memory.New())

	var requested []attestor.InstanceUUID

	fixture.reader.EXPECT().
		ReadInstanceByUUID(mock.Anything, guestUUID, mock.Anything).
		RunAndReturn(func(
			_ context.Context,
			instanceUUID attestor.InstanceUUID,
			_ attestor.ProjectName,
		) (attestor.InstanceRecord, error) {
			requested = append(requested, instanceUUID)

			return liveRecord(), nil
		})

	id, secret := fixture.mint(t)

	// A hostile guest presents its own valid nonce while claiming another
	// instance. The claim is not weighed against the binding, it is refused:
	// there is no field on this endpoint through which a caller can name an
	// instance at all. Any read for otherUUID would fail this test too, because
	// the mock has no expectation for it.
	claimed := fixture.post(t, redeemPath,
		`{"nonce_id":"`+string(id)+`","nonce":"`+secret+
			`","instance_uuid":"`+string(otherUUID)+`","project":"other-project"}`)

	require.Equal(t, http.StatusBadRequest, claimed.Code, claimed.Body.String())
	require.JSONEq(t, `{"error":"`+codeInvalidRequest+`"}`, claimed.Body.String())

	fixture.writer.EXPECT().ClearBootstrap(mock.Anything, guestProject, guestName).Return(nil).Once()

	// The same guest forwarding the four-field document it actually read
	// succeeds, and the identity it receives is the bound one.
	response := fixture.post(t, redeemPath,
		`{"nonce_id":"`+string(id)+`","nonce":"`+secret+
			`","broker_url":"https://broker.invalid`+redeemPath+
			`","broker_fingerprint":"6f0a1e2c3b4d5e"}`)

	require.Equal(t, http.StatusOK, response.Code, response.Body.String())

	redeemed := guestAnswerOf(t, response.Body.Bytes())
	require.Equal(t, guestUUID, redeemed.InstanceUUID)
	require.Equal(t, guestName, redeemed.InstanceName)
	require.Equal(t, guestProject, redeemed.Project)
	require.Contains(t, redeemed.Selectors, attestor.Selector("incus:uuid:"+string(guestUUID)))
	require.NotContains(t, redeemed.Selectors, attestor.Selector("incus:uuid:"+string(otherUUID)))

	require.NotEmpty(t, requested)

	for _, instanceUUID := range requested {
		require.Equal(t, guestUUID, instanceUUID, "the read path resolved only the bound instance")
	}

	require.NotContains(t, fixture.logs.String(), secret)
}

func TestRedeemClearsBootstrapKeyAfterRedemptionCommits(t *testing.T) {
	backing := memory.New()
	store := noncemocks.NewMockStore(t)

	var order []string

	store.EXPECT().Put(mock.Anything, mock.Anything).
		RunAndReturn(func(ctx context.Context, record nonce.Record) error {
			order = append(order, "put")

			return backing.Put(ctx, record)
		}).Once()

	store.EXPECT().Get(mock.Anything, mock.Anything).
		RunAndReturn(func(ctx context.Context, id nonce.NonceID) (nonce.Record, error) {
			order = append(order, "get")

			return backing.Get(ctx, id)
		}).Once()

	store.EXPECT().ConsumeOnce(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		RunAndReturn(func(
			ctx context.Context,
			id nonce.NonceID,
			hash nonce.NonceHash,
			now time.Time,
		) (nonce.Record, error) {
			order = append(order, "consume")

			return backing.ConsumeOnce(ctx, id, hash, now)
		}).Once()

	fixture := newFixture(t, store)
	fixture.reader.EXPECT().
		ReadInstanceByUUID(mock.Anything, guestUUID, mock.Anything).
		Return(liveRecord(), nil)

	payload := new(string)
	fixture.writer.EXPECT().
		WriteBootstrap(mock.Anything, guestProject, guestName, mock.Anything).
		RunAndReturn(func(_ context.Context, _ attestor.ProjectName, _ attestor.InstanceName, written string) error {
			order = append(order, "write")
			*payload = written

			return nil
		}).Once()

	fixture.writer.EXPECT().ClearBootstrap(mock.Anything, guestProject, guestName).
		RunAndReturn(func(_ context.Context, _ attestor.ProjectName, _ attestor.InstanceName) error {
			order = append(order, "clear")

			return nil
		}).Once()

	minted := fixture.post(t, mintPath, `{"instance_uuid":"`+string(guestUUID)+`"}`)
	require.Equal(t, http.StatusCreated, minted.Code, minted.Body.String())

	var response mintResponse
	require.NoError(t, json.Unmarshal(minted.Body.Bytes(), &response))

	redeemed := fixture.post(t, redeemPath, redeemBody(response.NonceID, secretFromPayload(t, *payload)))
	require.Equal(t, http.StatusOK, redeemed.Code, redeemed.Body.String())

	require.Equal(t, []string{"put", "write", "get", "consume", "clear"}, order,
		"the consume commits before the key is cleared, so a crash between them leaves a consumed value")
}

func TestRedeemSucceedsWhenClearFails(t *testing.T) {
	fixture := newFixture(t, memory.New())
	fixture.reader.EXPECT().
		ReadInstanceByUUID(mock.Anything, guestUUID, mock.Anything).
		Return(liveRecord(), nil)

	id, secret := fixture.mint(t)

	fixture.writer.EXPECT().ClearBootstrap(mock.Anything, guestProject, guestName).
		Return(errors.New("incus refused the clear")).Once()

	response := fixture.post(t, redeemPath, redeemBody(id, secret))

	// The consume already committed. What is left in the instance configuration
	// is a value that no longer redeems, so the guest still gets its answer and
	// the leftover is recorded instead.
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	require.Contains(t, fixture.logs.String(), "bootstrap key not cleared after redemption committed")
	require.NotContains(t, fixture.logs.String(), secret)
}

func TestRedeemReturnsTheExchangeSVIDAsAUsablePEMTriple(t *testing.T) {
	fixture := newFixture(t, memory.New())
	fixture.reader.EXPECT().
		ReadInstanceByUUID(mock.Anything, guestUUID, mock.Anything).
		Return(liveRecord(), nil)

	id, secret := fixture.mint(t)
	fixture.writer.EXPECT().ClearBootstrap(mock.Anything, guestProject, guestName).Return(nil).Once()

	response := fixture.post(t, redeemPath, redeemBody(id, secret))
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())

	redeemed := guestAnswerOf(t, response.Body.Bytes())

	// The identity the guest receives is the one P9 fixed, and its expiry is the
	// leaf's NotAfter rather than anything this service invented.
	require.Equal(t, exchangeSPIFFEID, redeemed.ExchangeSPIFFEID)
	require.True(t, fixture.leaf.NotAfter.Equal(redeemed.ExchangeExpiresAt))

	// The chain and the bundle are PEM the agent can load, and the chain's leaf is
	// the certificate the Broker API delivered.
	chain := parseCertificatePEM(t, redeemed.ExchangeCertChainPEM)
	require.Len(t, chain, 1)
	require.Equal(t, fixture.leaf.Raw, chain[0].Raw)
	require.Len(t, parseCertificatePEM(t, redeemed.ExchangeBundlePEM), 1)

	// The key is a PKCS#8 PEM block, and it is the key for that leaf: without
	// proof of possession x509pop refuses the exchange.
	block, rest := pem.Decode([]byte(redeemed.ExchangeKeyPEM))
	require.NotNil(t, block)
	require.Empty(t, rest)
	require.Equal(t, pemTypePrivateKey, block.Type)

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	require.NoError(t, err)

	key, ok := parsed.(*ecdsa.PrivateKey)
	require.True(t, ok)
	require.True(t, key.PublicKey.Equal(chain[0].PublicKey))

	// The P8 observable survives: all six frozen selectors are still answered.
	require.Len(t, redeemed.Selectors, 6)
	require.Contains(t, redeemed.Selectors, attestor.Selector("incus:uuid:"+string(guestUUID)))

	// The reference submitted to the Broker API is the vendor type the host
	// agent's allowlist and attestor plugin agree on, and it claims only the
	// server-resolved binding.
	require.Len(t, fixture.exchange.references, 1)
	require.Equal(t, referenceTypeURL, fixture.exchange.references[0].GetTypeUrl())

	claim := new(incusv1alpha1.IncusInstanceReference)
	require.NoError(t, fixture.exchange.references[0].UnmarshalTo(claim))
	require.Equal(t, string(guestUUID), claim.GetInstanceUuid())
	require.Equal(t, string(guestProject), claim.GetProject())

	// Nothing about the key reached the log, and the answer that carried it was
	// never logged as a body.
	require.NotContains(t, fixture.logs.String(), redeemed.ExchangeKeyPEM)
	require.NotContains(t, fixture.logs.String(), "PRIVATE KEY")
	require.Contains(t, fixture.logs.String(), string(exchangeSPIFFEID))
}

// parseCertificatePEM decodes every certificate block in encoded.
func parseCertificatePEM(t *testing.T, encoded string) []*x509.Certificate {
	t.Helper()

	var certificates []*x509.Certificate

	rest := []byte(encoded)

	for {
		var block *pem.Block

		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		require.Equal(t, pemTypeCertificate, block.Type)

		certificate, err := x509.ParseCertificate(block.Bytes)
		require.NoError(t, err)

		certificates = append(certificates, certificate)
	}

	require.Empty(t, rest)

	return certificates
}

func TestRedeemBurnsTheNonceWhenTheExchangeFetchFails(t *testing.T) {
	// Every case answers the same body code, because a guest can act on exactly
	// one fact: the nonce is gone. The status still separates what an operator
	// must fix from what may clear on its own, and the log carries the class.
	tests := map[string]struct {
		failure    error
		wantStatus int
		wantClass  string
	}{
		"reference type outside the broker allowlist": {
			failure:    broker.ErrReferenceTypeDenied,
			wantStatus: http.StatusInternalServerError,
			wantClass:  classReferenceTypeDenied,
		},
		"no registration entry matches the selector": {
			failure:    broker.ErrPermissionDenied,
			wantStatus: http.StatusInternalServerError,
			wantClass:  classPermissionDenied,
		},
		"the broker endpoint rejected the request": {
			failure:    broker.ErrInvalidRequest,
			wantStatus: http.StatusInternalServerError,
			wantClass:  classInvalidRequest,
		},
		"broker socket unreachable": {
			failure:    broker.ErrTransport,
			wantStatus: http.StatusServiceUnavailable,
			wantClass:  classTransport,
		},
		"broker call timed out": {
			failure:    broker.ErrTimeout,
			wantStatus: http.StatusServiceUnavailable,
			wantClass:  classTimeout,
		},
		"stream ended without an SVID": {
			failure:    broker.ErrNoSVID,
			wantStatus: http.StatusServiceUnavailable,
			wantClass:  classNoSVID,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newFixture(t, memory.New())
			fixture.reader.EXPECT().
				ReadInstanceByUUID(mock.Anything, guestUUID, mock.Anything).
				Return(liveRecord(), nil)

			id, secret := fixture.mint(t)
			fixture.writer.EXPECT().
				ClearBootstrap(mock.Anything, guestProject, guestName).Return(nil).Once()
			fixture.exchange.err = test.failure

			response := fixture.post(t, redeemPath, redeemBody(id, secret))

			// A Broker failure is this service's fault, never a refused
			// presentation: the guest presented a valid nonce and is owed an
			// answer that says so. The status class is preserved; the code is the
			// one that tells the guest the nonce is gone.
			require.Equal(t, test.wantStatus, response.Code, response.Body.String())
			require.JSONEq(t, `{"error":"`+codeNonceConsumedWithoutSVID+`"}`, response.Body.String())
			require.NotContains(t, response.Body.String(), codeInternal)
			require.NotContains(t, response.Body.String(), codeUnavailable)

			logs := fixture.logs.String()
			require.Contains(t, logs, "nonce consumed but no exchange SVID was issued")
			require.Contains(t, logs, fieldFailureClass+"="+test.wantClass)
			require.Contains(t, logs, fieldNonceID+"="+string(id))
			require.Contains(t, logs, fieldInstanceUUID+"="+string(guestUUID))
			require.Contains(t, logs, fieldCode+"="+codeNonceConsumedWithoutSVID)
			require.Contains(t, logs, fieldOutcome+"=burned")
			require.NotContains(t, logs, fieldOutcome+"=denied")
			require.NotContains(t, logs, "bootstrap request denied")
			require.NotContains(t, logs, secret)

			// The nonce really was consumed before the Broker was called, and the
			// bootstrap key really was cleared: this guest is owed a fresh nonce,
			// not a retry.
			require.Contains(t, logs, "bootstrap key cleared")

			replay := fixture.post(t, redeemPath, redeemBody(id, secret))
			require.Equal(t, http.StatusConflict, replay.Code, replay.Body.String())
			require.JSONEq(t, `{"error":"`+codeConflict+`"}`, replay.Body.String())
			require.Len(t, fixture.exchange.references, 1,
				"a spent nonce never reaches the Broker API a second time")
		})
	}
}

func TestRedeemBurnsTheNonceWhenTheDeliveredMaterialIsUnusable(t *testing.T) {
	fixture := newFixture(t, memory.New())
	fixture.reader.EXPECT().
		ReadInstanceByUUID(mock.Anything, guestUUID, mock.Anything).
		Return(liveRecord(), nil)

	id, secret := fixture.mint(t)
	fixture.writer.EXPECT().ClearBootstrap(mock.Anything, guestProject, guestName).Return(nil).Once()

	// An SVID with no private key is structurally useless: x509pop cannot prove
	// possession without it, so handing the guest the chain alone would be a
	// success answer to a failed bootstrap.
	fixture.exchange.svid.KeyDER = nil

	response := fixture.post(t, redeemPath, redeemBody(id, secret))
	require.Equal(t, http.StatusInternalServerError, response.Code, response.Body.String())
	require.JSONEq(t, `{"error":"`+codeNonceConsumedWithoutSVID+`"}`, response.Body.String())
	require.Contains(t, fixture.logs.String(), fieldFailureClass+"="+classMaterialInvalid)
}

func TestRedeemBurnsTheNonceWhenTheDerivationFailsAfterTheConsume(t *testing.T) {
	const seededID nonce.NonceID = "9c0d1e2f3a4b5c6d"

	fixture := newFixture(t, memory.New())
	seed(t, fixture.store, boundRecord(seededID, time.Now().Add(time.Minute), false))

	stopped := liveRecord()
	stopped.Status = attestor.InstanceStatusStopped

	// The redemption reads a running instance and commits; the derivation then
	// reads it again and finds it stopped, which is a fault the P8 mapping calls a
	// 409. The nonce is spent by then, so the status stays 409 and the code says
	// the guest got nothing for it.
	fixture.reader.EXPECT().ReadInstanceByUUID(mock.Anything, guestUUID, guestProject).
		Return(liveRecord(), nil).Once()
	fixture.reader.EXPECT().ReadInstanceByUUID(mock.Anything, guestUUID, guestProject).
		Return(stopped, nil).Once()
	fixture.writer.EXPECT().ClearBootstrap(mock.Anything, guestProject, guestName).Return(nil).Once()

	response := fixture.post(t, redeemPath, redeemBody(seededID, knownSecret))
	require.Equal(t, http.StatusConflict, response.Code, response.Body.String())
	require.JSONEq(t, `{"error":"`+codeNonceConsumedWithoutSVID+`"}`, response.Body.String())

	logs := fixture.logs.String()
	require.Contains(t, logs, "nonce consumed but no exchange SVID was issued")
	require.Contains(t, logs, fieldFailureClass+"="+classSelectorDerivation)
	require.Contains(t, logs, fieldOutcome+"=burned")
	require.NotContains(t, logs, fieldOutcome+"=denied",
		"a derivation failure after the consume is a burn, not a refusal")
	require.Empty(t, fixture.exchange.references,
		"a derivation failure costs the nonce and nothing else: no credential was issued")
}

func TestBurnedNonceIsNeverConflatedWithARefusedPresentation(t *testing.T) {
	const (
		unknownID  nonce.NonceID = "a0b1c2d3e4f5a6b7"
		expiredID  nonce.NonceID = "b1c2d3e4f5a6b7c8"
		consumedID nonce.NonceID = "c2d3e4f5a6b7c8d9"
		derivedID  nonce.NonceID = "d3e4f5a6b7c8d9e0"
	)

	// The two shapes a guest is entitled to keep reading: a refused presentation
	// says nothing about why, and a spent nonce says exactly that it is spent.
	const (
		refusedUnauthorized = `{"error":"` + codeUnauthorized + `"}`
		refusedConflict     = `{"error":"` + codeConflict + `"}`
		burned              = `{"error":"` + codeNonceConsumedWithoutSVID + `"}`
	)

	unknown := newFixture(t, memory.New())
	unknownAnswer := unknown.post(t, redeemPath, redeemBody(unknownID, knownSecret))

	expired := newFixture(t, memory.New())
	seed(t, expired.store, boundRecord(expiredID, time.Now().Add(-time.Minute), false))
	expired.reader.EXPECT().ReadInstanceByUUID(mock.Anything, guestUUID, guestProject).
		Return(liveRecord(), nil).Once()

	expiredAnswer := expired.post(t, redeemPath, redeemBody(expiredID, knownSecret))

	replayed := newFixture(t, memory.New())
	seed(t, replayed.store, boundRecord(consumedID, time.Now().Add(time.Minute), true))
	replayed.reader.EXPECT().ReadInstanceByUUID(mock.Anything, guestUUID, guestProject).
		Return(liveRecord(), nil).Once()

	replayedAnswer := replayed.post(t, redeemPath, redeemBody(consumedID, knownSecret))

	// A burn whose status is a 5xx, and a burn whose status is the very 409 a
	// replay answers with. The second is the case that would be indistinguishable
	// without the distinct code.
	transport := newFixture(t, memory.New())
	transport.reader.EXPECT().ReadInstanceByUUID(mock.Anything, guestUUID, mock.Anything).
		Return(liveRecord(), nil)
	transportID, transportSecret := transport.mint(t)
	transport.writer.EXPECT().ClearBootstrap(mock.Anything, guestProject, guestName).Return(nil).Once()
	transport.exchange.err = broker.ErrNoSVID

	transportAnswer := transport.post(t, redeemPath, redeemBody(transportID, transportSecret))

	stopped := liveRecord()
	stopped.Status = attestor.InstanceStatusStopped

	derived := newFixture(t, memory.New())
	seed(t, derived.store, boundRecord(derivedID, time.Now().Add(time.Minute), false))
	derived.reader.EXPECT().ReadInstanceByUUID(mock.Anything, guestUUID, guestProject).
		Return(liveRecord(), nil).Once()
	derived.reader.EXPECT().ReadInstanceByUUID(mock.Anything, guestUUID, guestProject).
		Return(stopped, nil).Once()
	derived.writer.EXPECT().ClearBootstrap(mock.Anything, guestProject, guestName).Return(nil).Once()

	derivedAnswer := derived.post(t, redeemPath, redeemBody(derivedID, knownSecret))

	// The pre-consumption bodies are unchanged, byte for byte. A guest, and the
	// live-run harness, may keep depending on them.
	require.Equal(t, http.StatusUnauthorized, unknownAnswer.Code, unknownAnswer.Body.String())
	require.JSONEq(t, refusedUnauthorized, unknownAnswer.Body.String())
	require.Equal(t, http.StatusConflict, expiredAnswer.Code, expiredAnswer.Body.String())
	require.JSONEq(t, refusedConflict, expiredAnswer.Body.String())
	require.Equal(t, http.StatusConflict, replayedAnswer.Code, replayedAnswer.Body.String())
	require.JSONEq(t, refusedConflict, replayedAnswer.Body.String())

	// No refusal ever carries the burn code: "your nonce was rejected" and "your
	// nonce was accepted and spent for nothing" are different facts.
	for _, refusal := range []*httptest.ResponseRecorder{unknownAnswer, expiredAnswer, replayedAnswer} {
		require.NotContains(t, refusal.Body.String(), codeNonceConsumedWithoutSVID)
	}

	require.Equal(t, http.StatusServiceUnavailable, transportAnswer.Code, transportAnswer.Body.String())
	require.JSONEq(t, burned, transportAnswer.Body.String())
	require.Equal(t, http.StatusConflict, derivedAnswer.Code, derivedAnswer.Body.String())
	require.JSONEq(t, burned, derivedAnswer.Body.String())

	// Same status, different body: the status class is preserved and the guest can
	// still tell a replay from a burn.
	require.Equal(t, replayedAnswer.Code, derivedAnswer.Code)
	require.NotEqual(t, replayedAnswer.Body.Bytes(), derivedAnswer.Body.Bytes(),
		"a 409 refusal and a 409 burn must not be the same answer: one may be retried never, the other never at all")
}

func TestBurnIsLoggedWithTheNonceAndFailureClassAndNoKeyMaterial(t *testing.T) {
	fixture := newFixture(t, memory.New())
	fixture.reader.EXPECT().
		ReadInstanceByUUID(mock.Anything, guestUUID, mock.Anything).
		Return(liveRecord(), nil)

	id, secret := fixture.mint(t)
	fixture.writer.EXPECT().ClearBootstrap(mock.Anything, guestProject, guestName).Return(nil).Once()

	// The Broker delivers a real private key and an unparseable chain, so the burn
	// happens with key material in hand. That is the only burn that can leak one,
	// which makes it the burn worth asserting on.
	keyDER, err := x509.MarshalPKCS8PrivateKey(fixture.signer)
	require.NoError(t, err)

	fixture.exchange.svid.KeyDER = keyDER
	fixture.exchange.svid.ChainDER = []byte("not a certificate")

	response := fixture.post(t, redeemPath, redeemBody(id, secret))
	require.Equal(t, http.StatusInternalServerError, response.Code, response.Body.String())
	require.JSONEq(t, `{"error":"`+codeNonceConsumedWithoutSVID+`"}`, response.Body.String())

	logs := fixture.logs.String()

	// The fixed message is the operator's alert surface, and the record has to say
	// which nonce, which guest, and what failed.
	require.Contains(t, logs, "nonce consumed but no exchange SVID was issued")
	require.Contains(t, logs, "level=ERROR")
	require.Contains(t, logs, fieldNonceID+"="+string(id))
	require.Contains(t, logs, fieldInstanceUUID+"="+string(guestUUID))
	require.Contains(t, logs, fieldFailureClass+"="+classMaterialInvalid)
	require.Contains(t, logs, fieldOutcome+"=burned")
	require.Contains(t, logs, fieldCode+"="+codeNonceConsumedWithoutSVID)

	// Appendix D: neither secret may appear, in any encoding the record could have
	// used. The base64 prefix catches a raw DER dump and a PEM block alike.
	require.NotContains(t, logs, secret)
	require.NotContains(t, logs, "PRIVATE KEY")
	require.NotContains(t, logs, base64.StdEncoding.EncodeToString(keyDER)[:32])
	require.NotContains(t, logs, redactedExchangeKey,
		"a burn record has no key field at all, redacted or otherwise")
}

func TestExchangeKeyPEMNeverPrints(t *testing.T) {
	const material = "-----BEGIN PRIVATE KEY-----\nc2VjcmV0IGtleSBtYXRlcmlhbA==\n-----END PRIVATE KEY-----\n"

	key := newExchangeKeyPEM([]byte(material))

	for _, rendered := range []string{
		fmt.Sprintf("%v", key),
		fmt.Sprintf("%s", key),
		fmt.Sprintf("%q", key),
		fmt.Sprintf("%#v", key),
		fmt.Sprintf("%d", key),
		fmt.Sprintf("%x", key),
		key.String(),
		key.GoString(),
		fmt.Sprintf("%v", []exchangeKeyPEM{key}),
		fmt.Sprintf("%v", redeemResponse{ExchangeKeyPEM: key}),
		fmt.Sprintf("%v", &key),
		fmt.Errorf("exchange failed: %v", key).Error(),
	} {
		require.NotContains(t, rendered, material)
		require.NotContains(t, rendered, "PRIVATE KEY")
		require.Contains(t, rendered, redactedExchangeKey)
	}

	// slog is the path that actually matters: every failure record this service
	// writes goes through it.
	var logged bytes.Buffer

	logger := slog.New(slog.NewJSONHandler(&logged, nil))
	logger.InfoContext(t.Context(), "exchange", "key", key, "response",
		redeemResponse{NonceID: "0123456789abcdef", ExchangeKeyPEM: key})

	require.NotContains(t, logged.String(), material)
	require.NotContains(t, logged.String(), "PRIVATE KEY")
	require.Contains(t, logged.String(), redactedExchangeKey)

	// The one deliberate reveal is the marshalling that answers the guest.
	encoded, err := json.Marshal(key)
	require.NoError(t, err)
	require.JSONEq(t, strconv.Quote(material), string(encoded))
}

func TestRedeemResponseRedactionCannotRegress(t *testing.T) {
	const material = "-----BEGIN PRIVATE KEY-----\nZmFrZSBleGNoYW5nZSBrZXk=\n-----END PRIVATE KEY-----\n"

	answer := redeemResponse{
		NonceID:              "0123456789abcdef",
		InstanceUUID:         guestUUID,
		InstanceName:         guestName,
		Generation:           guestGeneration,
		Project:              guestProject,
		Selectors:            []attestor.Selector{"incus:uuid:" + attestor.Selector(guestUUID)},
		ExchangeSPIFFEID:     exchangeSPIFFEID,
		ExchangeCertChainPEM: "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n",
		ExchangeKeyPEM:       newExchangeKeyPEM([]byte(material)),
		ExchangeBundlePEM:    "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n",
		ExchangeExpiresAt:    time.Now().Add(exchangeLifetime),
	}

	// These two methods are security controls, not conveniences. MarshalJSON on
	// this type deliberately reveals the key, so a sink that marshals instead of
	// formatting gets the key itself: losing either guard opens that path with no
	// other change to the package. This assertion is what makes that removal
	// noisy.
	require.Implements(t, (*slog.LogValuer)(nil), answer,
		"redeemResponse must keep LogValue: slog resolves it before a handler can marshal the struct")
	require.Implements(t, (*fmt.Stringer)(nil), answer,
		"redeemResponse must keep String: a %v or %+v on the composed answer would otherwise widen to its fields")

	// The JSON handler is the concrete leak: without LogValue it marshals the
	// attribute, and marshalling is the deliberate reveal.
	var jsonLogged bytes.Buffer

	slog.New(slog.NewJSONHandler(&jsonLogged, nil)).
		InfoContext(t.Context(), "answered", "response", answer)

	// The text handler is what this service actually installs, and it formats.
	var textLogged bytes.Buffer

	slog.New(slog.NewTextHandler(&textLogged, nil)).
		InfoContext(t.Context(), "answered", "response", answer)

	for _, rendered := range []string{
		jsonLogged.String(),
		textLogged.String(),
		fmt.Sprint(answer),
		fmt.Sprintf("%v", answer),
		fmt.Sprintf("%+v", answer),
		fmt.Sprintf("%#v", answer),
		fmt.Errorf("redemption answer: %v", answer).Error(),
	} {
		require.NotContains(t, rendered, material)
		require.NotContains(t, rendered, "PRIVATE KEY")
		require.Contains(t, rendered, redactedExchangeKey)
	}

	// The guest still receives usable material: the guard must not have been
	// implemented by breaking the one path that is supposed to reveal.
	encoded, err := json.Marshal(answer)
	require.NoError(t, err)

	var body map[string]any
	require.NoError(t, json.Unmarshal(encoded, &body))
	require.Equal(t, material, body["exchange_key_pem"])
}

func TestRedeemClearsTheBootstrapKeyOnceBeforeTheExchangeFetch(t *testing.T) {
	fixture := newFixture(t, memory.New())
	fixture.reader.EXPECT().
		ReadInstanceByUUID(mock.Anything, guestUUID, mock.Anything).
		Return(liveRecord(), nil)

	id, secret := fixture.mint(t)

	var order []string

	// Once() is the assertion that the clear is not repeated: mockery fails the
	// test on a second call, and the reaper leaves consumed records alone, so a
	// missed clear would never be compensated.
	fixture.writer.EXPECT().ClearBootstrap(mock.Anything, guestProject, guestName).
		RunAndReturn(func(_ context.Context, _ attestor.ProjectName, _ attestor.InstanceName) error {
			order = append(order, "clear")

			return nil
		}).Once()

	fixture.exchange.err = broker.ErrTransport
	fixture.exchange.observe = func() { order = append(order, "fetch") }

	response := fixture.post(t, redeemPath, redeemBody(id, secret))
	require.Equal(t, http.StatusServiceUnavailable, response.Code, response.Body.String())
	require.Len(t, fixture.exchange.references, 1)

	// The secret left the guest's configuration before the Broker was asked for
	// anything, so a Broker failure cannot leave a readable value behind.
	require.Equal(t, []string{"clear", "fetch"}, order)
}

func TestFailureStatusMapping(t *testing.T) {
	const seededID nonce.NonceID = "0123456789abcdef"

	tests := []struct {
		name       string
		store      func() nonce.Store
		arrange    func(t *testing.T, f *fixture) (string, string, string)
		wantStatus int
		wantCode   string
	}{
		{
			name:  "mint with an unknown instance",
			store: func() nonce.Store { return memory.New() },
			arrange: func(_ *testing.T, f *fixture) (string, string, string) {
				f.reader.EXPECT().ReadInstanceByUUID(mock.Anything, guestUUID, mock.Anything).
					Return(attestor.InstanceRecord{}, attestor.ErrInstanceNotFound).Once()

				return http.MethodPost, mintPath, `{"instance_uuid":"` + string(guestUUID) + `"}`
			},
			wantStatus: http.StatusConflict,
			wantCode:   codeConflict,
		},
		{
			name:  "mint with an ambiguous instance",
			store: func() nonce.Store { return memory.New() },
			arrange: func(_ *testing.T, f *fixture) (string, string, string) {
				f.reader.EXPECT().ReadInstanceByUUID(mock.Anything, guestUUID, mock.Anything).
					Return(attestor.InstanceRecord{}, attestor.ErrAmbiguousReference).Once()

				return http.MethodPost, mintPath, `{"instance_uuid":"` + string(guestUUID) + `"}`
			},
			wantStatus: http.StatusConflict,
			wantCode:   codeConflict,
		},
		{
			name:  "mint with a refused Incus credential",
			store: func() nonce.Store { return memory.New() },
			arrange: func(_ *testing.T, f *fixture) (string, string, string) {
				f.reader.EXPECT().ReadInstanceByUUID(mock.Anything, guestUUID, mock.Anything).
					Return(attestor.InstanceRecord{}, attestor.ErrBackendUnauthorized).Once()

				return http.MethodPost, mintPath, `{"instance_uuid":"` + string(guestUUID) + `"}`
			},
			wantStatus: http.StatusInternalServerError,
			wantCode:   codeInternal,
		},
		{
			name:  "mint against a misconfigured Incus",
			store: func() nonce.Store { return memory.New() },
			arrange: func(_ *testing.T, f *fixture) (string, string, string) {
				f.reader.EXPECT().ReadInstanceByUUID(mock.Anything, guestUUID, mock.Anything).
					Return(attestor.InstanceRecord{}, attestor.ErrBackendPermanent).Once()

				return http.MethodPost, mintPath, `{"instance_uuid":"` + string(guestUUID) + `"}`
			},
			wantStatus: http.StatusInternalServerError,
			wantCode:   codeInternal,
		},
		{
			name:  "mint against an unreachable Incus",
			store: func() nonce.Store { return memory.New() },
			arrange: func(_ *testing.T, f *fixture) (string, string, string) {
				f.reader.EXPECT().ReadInstanceByUUID(mock.Anything, guestUUID, mock.Anything).
					Return(attestor.InstanceRecord{}, attestor.ErrBackendUnavailable).Once()

				return http.MethodPost, mintPath, `{"instance_uuid":"` + string(guestUUID) + `"}`
			},
			wantStatus: http.StatusServiceUnavailable,
			wantCode:   codeUnavailable,
		},
		{
			name: "mint with a broken nonce store",
			store: func() nonce.Store {
				store := &noncemocks.MockStore{}
				store.EXPECT().Put(mock.Anything, mock.Anything).Return(errors.New("store backend is gone"))

				return store
			},
			arrange: func(_ *testing.T, f *fixture) (string, string, string) {
				f.reader.EXPECT().ReadInstanceByUUID(mock.Anything, guestUUID, mock.Anything).
					Return(liveRecord(), nil).Once()

				return http.MethodPost, mintPath, `{"instance_uuid":"` + string(guestUUID) + `"}`
			},
			wantStatus: http.StatusServiceUnavailable,
			wantCode:   codeUnavailable,
		},
		{
			name:  "mint with a failing bootstrap write",
			store: func() nonce.Store { return memory.New() },
			arrange: func(_ *testing.T, f *fixture) (string, string, string) {
				f.reader.EXPECT().ReadInstanceByUUID(mock.Anything, guestUUID, mock.Anything).
					Return(liveRecord(), nil).Once()
				f.writer.EXPECT().WriteBootstrap(mock.Anything, guestProject, guestName, mock.Anything).
					Return(errors.New("patch failed")).Once()

				return http.MethodPost, mintPath, `{"instance_uuid":"` + string(guestUUID) + `"}`
			},
			wantStatus: http.StatusServiceUnavailable,
			wantCode:   codeUnavailable,
		},
		{
			name:  "mint with a bootstrap write the credential may not perform",
			store: func() nonce.Store { return memory.New() },
			arrange: func(_ *testing.T, f *fixture) (string, string, string) {
				f.reader.EXPECT().ReadInstanceByUUID(mock.Anything, guestUUID, mock.Anything).
					Return(liveRecord(), nil).Once()
				f.writer.EXPECT().WriteBootstrap(mock.Anything, guestProject, guestName, mock.Anything).
					Return(attestor.ErrBackendUnauthorized).Once()

				return http.MethodPost, mintPath, `{"instance_uuid":"` + string(guestUUID) + `"}`
			},
			wantStatus: http.StatusInternalServerError,
			wantCode:   codeInternal,
		},
		{
			name:  "mint without an instance uuid",
			store: func() nonce.Store { return memory.New() },
			arrange: func(_ *testing.T, _ *fixture) (string, string, string) {
				return http.MethodPost, mintPath, `{"project":"spike-spiffe"}`
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   codeInvalidRequest,
		},
		{
			name:  "mint with a malformed body",
			store: func() nonce.Store { return memory.New() },
			arrange: func(_ *testing.T, _ *fixture) (string, string, string) {
				return http.MethodPost, mintPath, `{"instance_uuid":`
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   codeInvalidRequest,
		},
		{
			name:  "mint with the wrong method",
			store: func() nonce.Store { return memory.New() },
			arrange: func(_ *testing.T, _ *fixture) (string, string, string) {
				return http.MethodGet, mintPath, ""
			},
			wantStatus: http.StatusMethodNotAllowed,
			wantCode:   codeMethodNotAllowed,
		},
		{
			name:  "redeem an unknown nonce",
			store: func() nonce.Store { return memory.New() },
			arrange: func(_ *testing.T, _ *fixture) (string, string, string) {
				return http.MethodPost, redeemPath, redeemBody(seededID, knownSecret)
			},
			wantStatus: http.StatusUnauthorized,
			wantCode:   codeUnauthorized,
		},
		{
			name:  "redeem with a wrong secret",
			store: func() nonce.Store { return memory.New() },
			arrange: func(t *testing.T, f *fixture) (string, string, string) {
				t.Helper()
				seed(t, f.store, boundRecord(seededID, time.Now().Add(time.Minute), false))
				f.reader.EXPECT().ReadInstanceByUUID(mock.Anything, guestUUID, guestProject).
					Return(liveRecord(), nil).Once()

				return http.MethodPost, redeemPath, redeemBody(seededID, "0000000000000000")
			},
			wantStatus: http.StatusUnauthorized,
			wantCode:   codeUnauthorized,
		},
		{
			name:  "redeem without a secret",
			store: func() nonce.Store { return memory.New() },
			arrange: func(_ *testing.T, _ *fixture) (string, string, string) {
				return http.MethodPost, redeemPath, `{"nonce_id":"` + string(seededID) + `"}`
			},
			wantStatus: http.StatusUnauthorized,
			wantCode:   codeUnauthorized,
		},
		{
			name:  "redeem an expired nonce",
			store: func() nonce.Store { return memory.New() },
			arrange: func(t *testing.T, f *fixture) (string, string, string) {
				t.Helper()
				seed(t, f.store, boundRecord(seededID, time.Now().Add(-time.Minute), false))
				f.reader.EXPECT().ReadInstanceByUUID(mock.Anything, guestUUID, guestProject).
					Return(liveRecord(), nil).Once()

				return http.MethodPost, redeemPath, redeemBody(seededID, knownSecret)
			},
			wantStatus: http.StatusConflict,
			wantCode:   codeConflict,
		},
		{
			name:  "redeem a consumed nonce",
			store: func() nonce.Store { return memory.New() },
			arrange: func(t *testing.T, f *fixture) (string, string, string) {
				t.Helper()
				seed(t, f.store, boundRecord(seededID, time.Now().Add(time.Minute), true))
				f.reader.EXPECT().ReadInstanceByUUID(mock.Anything, guestUUID, guestProject).
					Return(liveRecord(), nil).Once()

				return http.MethodPost, redeemPath, redeemBody(seededID, knownSecret)
			},
			wantStatus: http.StatusConflict,
			wantCode:   codeConflict,
		},
		{
			name:  "redeem when the read path answers with another instance",
			store: func() nonce.Store { return memory.New() },
			arrange: func(t *testing.T, f *fixture) (string, string, string) {
				t.Helper()
				seed(t, f.store, boundRecord(seededID, time.Now().Add(time.Minute), false))

				live := liveRecord()
				live.UUID = otherUUID
				f.reader.EXPECT().ReadInstanceByUUID(mock.Anything, guestUUID, guestProject).
					Return(live, nil).Once()

				return http.MethodPost, redeemPath, redeemBody(seededID, knownSecret)
			},
			wantStatus: http.StatusConflict,
			wantCode:   codeConflict,
		},
		{
			name:  "redeem after a snapshot restore changed the generation",
			store: func() nonce.Store { return memory.New() },
			arrange: func(t *testing.T, f *fixture) (string, string, string) {
				t.Helper()
				seed(t, f.store, boundRecord(seededID, time.Now().Add(time.Minute), false))

				live := liveRecord()
				live.Generation = "99998888-7777-6666-5555-444433332222"
				f.reader.EXPECT().ReadInstanceByUUID(mock.Anything, guestUUID, guestProject).
					Return(live, nil).Once()

				return http.MethodPost, redeemPath, redeemBody(seededID, knownSecret)
			},
			wantStatus: http.StatusConflict,
			wantCode:   codeConflict,
		},
		{
			name: "redeem with a broken nonce store",
			store: func() nonce.Store {
				store := &noncemocks.MockStore{}
				store.EXPECT().Get(mock.Anything, mock.Anything).
					Return(nonce.Record{}, errors.New("store backend is gone"))

				return store
			},
			arrange: func(_ *testing.T, _ *fixture) (string, string, string) {
				return http.MethodPost, redeemPath, redeemBody(seededID, knownSecret)
			},
			wantStatus: http.StatusServiceUnavailable,
			wantCode:   codeUnavailable,
		},
		{
			name: "redeem when the consume itself fails",
			store: func() nonce.Store {
				store := &noncemocks.MockStore{}
				store.EXPECT().Get(mock.Anything, mock.Anything).
					Return(boundRecord(seededID, time.Now().Add(time.Minute), false), nil)
				store.EXPECT().ConsumeOnce(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(nonce.Record{}, errors.New("store backend is gone"))

				return store
			},
			arrange: func(_ *testing.T, f *fixture) (string, string, string) {
				f.reader.EXPECT().ReadInstanceByUUID(mock.Anything, guestUUID, guestProject).
					Return(liveRecord(), nil).Once()

				return http.MethodPost, redeemPath, redeemBody(seededID, knownSecret)
			},
			wantStatus: http.StatusServiceUnavailable,
			wantCode:   codeUnavailable,
		},
		{
			name:  "redeem an instance that stopped between the consume and the derivation",
			store: func() nonce.Store { return memory.New() },
			arrange: func(t *testing.T, f *fixture) (string, string, string) {
				t.Helper()
				seed(t, f.store, boundRecord(seededID, time.Now().Add(time.Minute), false))

				stopped := liveRecord()
				stopped.Status = attestor.InstanceStatusStopped

				f.reader.EXPECT().ReadInstanceByUUID(mock.Anything, guestUUID, guestProject).
					Return(liveRecord(), nil).Once()
				f.reader.EXPECT().ReadInstanceByUUID(mock.Anything, guestUUID, guestProject).
					Return(stopped, nil).Once()
				f.writer.EXPECT().ClearBootstrap(mock.Anything, guestProject, guestName).Return(nil).Once()

				return http.MethodPost, redeemPath, redeemBody(seededID, knownSecret)
			},
			// The status is the one the P8 mapping fixes for a stopped instance.
			// The code is not: this failure landed after the consume committed, so
			// the body says the nonce was spent for nothing. See
			// TestRedeemBurnsTheNonceWhenTheDerivationFailsAfterTheConsume.
			wantStatus: http.StatusConflict,
			wantCode:   codeNonceConsumedWithoutSVID,
		},
		{
			name:  "redeem with a malformed body",
			store: func() nonce.Store { return memory.New() },
			arrange: func(_ *testing.T, _ *fixture) (string, string, string) {
				return http.MethodPost, redeemPath, `not json`
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   codeInvalidRequest,
		},
		{
			name:  "redeem with the wrong method",
			store: func() nonce.Store { return memory.New() },
			arrange: func(_ *testing.T, _ *fixture) (string, string, string) {
				return http.MethodDelete, redeemPath, ""
			},
			wantStatus: http.StatusMethodNotAllowed,
			wantCode:   codeMethodNotAllowed,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFixture(t, test.store())
			method, path, body := test.arrange(t, fixture)

			response := fixture.do(t, method, path, body)

			require.Equal(t, test.wantStatus, response.Code, response.Body.String())
			require.JSONEq(t, `{"error":"`+test.wantCode+`"}`, response.Body.String())
			require.Equal(t, []string{contentTypeJSON}, response.Header().Values("Content-Type"))
		})
	}
}

func TestUnauthorizedAnswersAreIndistinguishable(t *testing.T) {
	const seededID nonce.NonceID = "fedcba9876543210"

	unknown := newFixture(t, memory.New())
	unknownAnswer := unknown.post(t, redeemPath, redeemBody(seededID, knownSecret))

	wrongSecret := newFixture(t, memory.New())
	seed(t, wrongSecret.store, boundRecord(seededID, time.Now().Add(time.Minute), false))
	wrongSecret.reader.EXPECT().ReadInstanceByUUID(mock.Anything, guestUUID, guestProject).
		Return(liveRecord(), nil).Once()

	wrongAnswer := wrongSecret.post(t, redeemPath, redeemBody(seededID, "1111111111111111"))

	require.Equal(t, http.StatusUnauthorized, unknownAnswer.Code)
	require.Equal(t, http.StatusUnauthorized, wrongAnswer.Code)
	require.Equal(t, unknownAnswer.Body.Bytes(), wrongAnswer.Body.Bytes(),
		"an unknown nonce and a wrong secret must be byte-identical, so the broker cannot enumerate nonce IDs")
	require.Equal(t, unknownAnswer.Header(), wrongAnswer.Header())
}

func TestBootstrapRoundTripOverHTTP(t *testing.T) {
	fixture := newFixture(t, memory.New())
	fixture.reader.EXPECT().
		ReadInstanceByUUID(mock.Anything, guestUUID, mock.Anything).
		Return(liveRecord(), nil)

	payload := fixture.expectWrite(t)
	fixture.writer.EXPECT().ClearBootstrap(mock.Anything, guestProject, guestName).Return(nil).Once()

	server := httptest.NewServer(fixture.service.Handler())
	defer server.Close()

	minted := roundTrip(t, server, mintPath, `{"instance_uuid":"`+string(guestUUID)+`"}`)
	require.Equal(t, http.StatusCreated, minted.status, minted.body)

	var response mintResponse
	require.NoError(t, json.Unmarshal([]byte(minted.body), &response))

	secret := secretFromPayload(t, *payload)
	require.NotContains(t, minted.body, secret)

	redeemed := roundTrip(t, server, redeemPath, redeemBody(response.NonceID, secret))
	require.Equal(t, http.StatusOK, redeemed.status, redeemed.body)
	require.NotContains(t, redeemed.body, secret)

	// What the guest gets off the wire is the material it writes to tmpfs and
	// points x509pop at, so the round trip has to prove all three PEM values
	// survive the transport, not just the status code.
	delivered := guestAnswerOf(t, []byte(redeemed.body))
	require.Equal(t, exchangeSPIFFEID, delivered.ExchangeSPIFFEID)
	require.Len(t, parseCertificatePEM(t, delivered.ExchangeCertChainPEM), 1)
	require.Len(t, parseCertificatePEM(t, delivered.ExchangeBundlePEM), 1)

	block, _ := pem.Decode([]byte(delivered.ExchangeKeyPEM))
	require.NotNil(t, block)

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	require.NoError(t, err)

	deliveredKey, ok := key.(*ecdsa.PrivateKey)
	require.True(t, ok)
	require.True(t, fixture.signer.PublicKey.Equal(deliveredKey.Public()))

	// The nonce is single use: the same presentation over the same transport is
	// refused now that the record is consumed.
	replayed := roundTrip(t, server, redeemPath, redeemBody(response.NonceID, secret))
	require.Equal(t, http.StatusConflict, replayed.status, replayed.body)
	require.JSONEq(t, `{"error":"`+codeConflict+`"}`, replayed.body)

	require.NotContains(t, fixture.logs.String(), secret)
	require.Contains(t, fixture.logs.String(), "bootstrap nonce redeemed")
}

// answer is one HTTP answer reduced to what the tests assert on.
type answer struct {
	// status is the HTTP status code.
	status int
	// body is the decoded response body.
	body string
}

// roundTrip posts body to one endpoint of a live test server, presenting the
// operator bearer token. The redeem path ignores it.
func roundTrip(t *testing.T, server *httptest.Server, path string, body string) answer {
	t.Helper()

	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+path, strings.NewReader(body))
	require.NoError(t, err)
	request.Header.Set(headerAuthorization, bearerScheme+" "+mintToken)

	response, err := server.Client().Do(request)
	require.NoError(t, err)

	defer func() {
		require.NoError(t, response.Body.Close())
	}()

	payload, err := io.ReadAll(response.Body)
	require.NoError(t, err)

	return answer{status: response.StatusCode, body: string(payload)}
}

func TestMintRefusesAnUnauthenticatedCaller(t *testing.T) {
	tests := []struct {
		name          string
		authorization string
	}{
		{name: "no authorization header at all", authorization: ""},
		{name: "a wrong token of the same length", authorization: bearerScheme + " " + wrongToken},
		{name: "an empty bearer token", authorization: bearerScheme + " "},
		{name: "the token under another scheme", authorization: "Basic " + mintToken},
		{name: "the token with no scheme", authorization: mintToken},
		{name: "a token with a prefix of the right one", authorization: bearerScheme + " " + mintToken[:16]},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// The doubles are created with t and given no expectations, so any
			// call to the read path or to the bootstrap writer fails this test.
			// That is the assertion: an unauthenticated caller reaches neither
			// Incus credential.
			fixture := newFixture(t, memory.New())

			response := fixture.doAs(t, http.MethodPost, mintPath,
				`{"instance_uuid":"`+string(guestUUID)+`"}`, test.authorization)

			require.Equal(t, http.StatusUnauthorized, response.Code, response.Body.String())
			require.JSONEq(t, `{"error":"`+codeUnauthorized+`"}`, response.Body.String())
			require.Equal(t, []string{contentTypeJSON}, response.Header().Values("Content-Type"))
			require.Equal(t, []string{bearerChallenge}, response.Header().Values(headerAuthenticate))

			fixture.reader.AssertNotCalled(t, "ReadInstanceByUUID")
			fixture.writer.AssertNotCalled(t, "WriteBootstrap")

			logs := fixture.logs.String()
			require.Contains(t, logs, "peer_address")
			require.NotContains(t, logs, mintToken)
			require.NotContains(t, logs, wrongToken)
		})
	}
}

func TestMintAcceptsTheOperatorTokenWithAnySchemeCase(t *testing.T) {
	fixture := newFixture(t, memory.New())
	fixture.reader.EXPECT().ReadInstanceByUUID(mock.Anything, guestUUID, mock.Anything).
		Return(liveRecord(), nil).Once()
	fixture.expectWrite(t)

	// RFC 7235 makes the scheme token case-insensitive, and curl, Python, and Go
	// clients do not agree on how to spell it.
	response := fixture.doAs(t, http.MethodPost, mintPath,
		`{"instance_uuid":"`+string(guestUUID)+`"}`, "bearer "+mintToken)

	require.Equal(t, http.StatusCreated, response.Code, response.Body.String())
}

func TestMintAppliesTheRequestedTTL(t *testing.T) {
	const requestedSeconds = 5

	fixture := newFixture(t, memory.New())
	fixture.reader.EXPECT().ReadInstanceByUUID(mock.Anything, guestUUID, mock.Anything).
		Return(liveRecord(), nil).Once()
	fixture.expectWrite(t)

	before := time.Now()
	response := fixture.post(t, mintPath,
		`{"instance_uuid":"`+string(guestUUID)+`","ttl_seconds":`+strconv.Itoa(requestedSeconds)+`}`)
	require.Equal(t, http.StatusCreated, response.Code, response.Body.String())

	var minted mintResponse
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &minted))

	// The requested window is what the nonce actually gets, not the minute the
	// fixture's minter would otherwise apply.
	requested := time.Duration(requestedSeconds) * time.Second
	require.WithinDuration(t, before.Add(requested), minted.ExpiresAt, time.Second)

	record, err := fixture.store.Get(t.Context(), minted.NonceID)
	require.NoError(t, err)
	require.WithinDuration(t, minted.ExpiresAt, record.ExpiresAt, 0)
}

func TestMintRefusesAMalformedOrOutOfRangeRequest(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "a negative ttl", body: `{"instance_uuid":"` + string(guestUUID) + `","ttl_seconds":-1}`},
		{name: "a zero ttl", body: `{"instance_uuid":"` + string(guestUUID) + `","ttl_seconds":0}`},
		{name: "a ttl above the maximum", body: `{"instance_uuid":"` + string(guestUUID) + `","ttl_seconds":601}`},
		{name: "a ttl that overflows a duration", body: `{"instance_uuid":"` + string(guestUUID) +
			`","ttl_seconds":9223372036854775807}`},
		{name: "a misspelled ttl field", body: `{"instance_uuid":"` + string(guestUUID) + `","ttl_second":5}`},
		{name: "an unknown field", body: `{"instance_uuid":"` + string(guestUUID) + `","force":true}`},
		{name: "a stale client's renamed uuid field", body: `{"uuid":"` + string(guestUUID) + `"}`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// No expectations again: a request this service cannot fully honour
			// must be refused before it spends an Incus credential.
			fixture := newFixture(t, memory.New())

			response := fixture.post(t, mintPath, test.body)

			require.Equal(t, http.StatusBadRequest, response.Code, response.Body.String())
			require.JSONEq(t, `{"error":"`+codeInvalidRequest+`"}`, response.Body.String())

			fixture.reader.AssertNotCalled(t, "ReadInstanceByUUID")
			fixture.writer.AssertNotCalled(t, "WriteBootstrap")
		})
	}
}

func TestMintIsWithdrawnWhenTheCallerGoesAway(t *testing.T) {
	store := memory.New()
	fixture := newFixture(t, store)
	fixture.reader.EXPECT().ReadInstanceByUUID(mock.Anything, guestUUID, mock.Anything).
		Return(liveRecord(), nil).Once()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	payload := new(string)
	fixture.writer.EXPECT().
		WriteBootstrap(mock.Anything, guestProject, guestName, mock.Anything).
		RunAndReturn(func(_ context.Context, _ attestor.ProjectName, _ attestor.InstanceName, written string) error {
			*payload = written
			// The Incus write has committed. The operator hangs up here, which
			// is the window in which a bearer credential would otherwise stay
			// live in the guest's configuration with nobody holding its ID.
			cancel()

			return nil
		}).Once()

	cleared := make(chan struct{}, 1)
	fixture.writer.EXPECT().ClearBootstrap(mock.Anything, guestProject, guestName).
		RunAndReturn(func(_ context.Context, _ attestor.ProjectName, _ attestor.InstanceName) error {
			cleared <- struct{}{}

			return nil
		}).Once()

	request := httptest.NewRequestWithContext(ctx, http.MethodPost, mintPath,
		strings.NewReader(`{"instance_uuid":"`+string(guestUUID)+`"}`))
	request.Header.Set(headerAuthorization, bearerScheme+" "+mintToken)
	fixture.service.Handler().ServeHTTP(httptest.NewRecorder(), request)

	require.Len(t, cleared, 1, "the bootstrap key of an unacknowledged mint is cleared")
	require.Zero(t, store.Len(), "the record of an unacknowledged mint is deleted")

	id := nonceIDFromPayload(t, *payload)
	_, err := store.Get(context.WithoutCancel(ctx), id)
	require.ErrorIs(t, err, nonce.ErrNonceNotFound)

	logs := fixture.logs.String()
	require.Contains(t, logs, "unacknowledged mint withdrawn")
	require.Contains(t, logs, string(id))
	require.NotContains(t, logs, secretFromPayload(t, *payload))
}

func TestMintWithdrawalYieldsToARedemptionThatWonTheRace(t *testing.T) {
	store := memory.New()
	fixture := newFixture(t, store)
	fixture.reader.EXPECT().ReadInstanceByUUID(mock.Anything, guestUUID, mock.Anything).
		Return(liveRecord(), nil).Once()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	payload := new(string)
	fixture.writer.EXPECT().
		WriteBootstrap(mock.Anything, guestProject, guestName, mock.Anything).
		RunAndReturn(func(_ context.Context, _ attestor.ProjectName, _ attestor.InstanceName, written string) error {
			*payload = written
			// The guest reads and redeems inside the same window in which the
			// operator hangs up. The consume commits first, so the compensation
			// must not clear a key the redemption path owns.
			id := nonceIDFromPayload(t, written)
			_, consumeErr := store.ConsumeOnce(t.Context(), id,
				nonce.HashSecret(nonce.NewSecret(secretFromPayload(t, written))), time.Now())
			require.NoError(t, consumeErr)
			cancel()

			return nil
		}).Once()

	request := httptest.NewRequestWithContext(ctx, http.MethodPost, mintPath,
		strings.NewReader(`{"instance_uuid":"`+string(guestUUID)+`"}`))
	request.Header.Set(headerAuthorization, bearerScheme+" "+mintToken)
	fixture.service.Handler().ServeHTTP(httptest.NewRecorder(), request)

	// No ClearBootstrap expectation exists, so a clear here would fail the test.
	require.Equal(t, 1, store.Len(), "a consumed record survives the compensation")
	require.Contains(t, fixture.logs.String(), "unacknowledged mint was redeemed before it could be withdrawn")
}

// reaperFixture is one wired reaper plus the doubles behind it.
type reaperFixture struct {
	// reader is the read-only Incus path the reaper re-resolves names through.
	reader *attestormocks.MockInstanceReader
	// writer is the bootstrap configuration writer.
	writer *noncemocks.MockBootstrapWriter
	// reaper is the subject under test.
	reaper *Reaper
	// logs captures everything the reaper logged.
	logs *bytes.Buffer
}

// newReaperFixture wires a reaper over store with the real nonce lifecycle core,
// so the consumed-record refusal under test is the core's own rule rather than a
// restatement of it.
func newReaperFixture(t *testing.T, store nonce.Store, expired expiredLister) *reaperFixture {
	t.Helper()

	reader := attestormocks.NewMockInstanceReader(t)
	writer := noncemocks.NewMockBootstrapWriter(t)
	logs := &bytes.Buffer{}

	reaper, err := NewReaper(ReaperConfig{
		Reader:     reader,
		Expired:    expired,
		Withdrawer: nonce.NewMinter(store, writer),
		Logger:     slog.New(slog.NewTextHandler(logs, nil)),
		Interval:   time.Minute,
		Timeout:    testCompensationTimeout,
	})
	require.NoError(t, err)

	return &reaperFixture{reader: reader, writer: writer, reaper: reaper, logs: logs}
}

func TestReaperWithdrawsAnExpiredUnredeemedNonce(t *testing.T) {
	const seededID nonce.NonceID = "1a2b3c4d5e6f7a8b"

	store := memory.New()
	fixture := newReaperFixture(t, store, store)
	seed(t, store, boundRecord(seededID, time.Now().Add(-time.Minute), false))

	fixture.reader.EXPECT().ReadInstanceByUUID(mock.Anything, guestUUID, guestProject).
		Return(liveRecord(), nil).Once()
	fixture.writer.EXPECT().ClearBootstrap(mock.Anything, guestProject, guestName).Return(nil).Once()

	fixture.reaper.sweep(t.Context())

	require.Zero(t, store.Len(), "the record is deleted once the key is cleared")

	logs := fixture.logs.String()
	require.Contains(t, logs, "expired nonce withdrawn")
	require.Contains(t, logs, string(seededID))
	require.Contains(t, logs, string(guestUUID))
}

func TestReaperLeavesAConsumedNonceAlone(t *testing.T) {
	const seededID nonce.NonceID = "2b3c4d5e6f7a8b9c"

	store := memory.New()
	fixture := newReaperFixture(t, store, store)
	seed(t, store, boundRecord(seededID, time.Now().Add(-time.Minute), true))

	// Neither double has an expectation, so a read or a clear here fails the
	// test. The consumed value in the instance configuration can no longer
	// redeem, and the record is what makes a replay answer "already used".
	fixture.reaper.sweep(t.Context())

	require.Equal(t, 1, store.Len(), "a consumed record survives the sweep")
	require.NotContains(t, fixture.logs.String(), "expired nonce withdrawn")
}

func TestReaperRefusesToClearANonceConsumedMidSweep(t *testing.T) {
	const seededID nonce.NonceID = "3c4d5e6f7a8b9c0d"

	expired := boundRecord(seededID, time.Now().Add(-time.Minute), false)

	store := noncemocks.NewMockStore(t)
	// The listing saw an unconsumed record; by the time the withdrawal looks
	// again, the redemption that committed just before expiry is visible. This
	// is the race the sweep must lose.
	store.EXPECT().Get(mock.Anything, seededID).
		Return(boundRecord(seededID, expired.ExpiresAt, true), nil).Once()

	lister := noncemocks.NewMockStore(t)
	lister.EXPECT().ListExpired(mock.Anything, mock.Anything).
		Return([]nonce.Record{expired}, nil).Once()

	fixture := newReaperFixture(t, store, lister)
	fixture.reader.EXPECT().ReadInstanceByUUID(mock.Anything, guestUUID, guestProject).
		Return(liveRecord(), nil).Once()

	// No ClearBootstrap and no Delete expectation: either call fails this test.
	fixture.reaper.sweep(t.Context())

	require.Contains(t, fixture.logs.String(), "expired nonce needed no withdrawal")
}

func TestReaperRetriesAfterAFailedClear(t *testing.T) {
	const seededID nonce.NonceID = "4d5e6f7a8b9c0d1e"

	store := memory.New()
	fixture := newReaperFixture(t, store, store)
	seed(t, store, boundRecord(seededID, time.Now().Add(-time.Minute), false))

	fixture.reader.EXPECT().ReadInstanceByUUID(mock.Anything, guestUUID, guestProject).
		Return(liveRecord(), nil).Twice()
	fixture.writer.EXPECT().ClearBootstrap(mock.Anything, guestProject, guestName).
		Return(errors.New("incus refused the clear")).Once()

	fixture.reaper.sweep(t.Context())

	require.Equal(t, 1, store.Len(),
		"a record whose key could not be cleared stays, because it is the only handle on that key")
	require.Contains(t, fixture.logs.String(), "retrying on the next sweep")

	fixture.writer.EXPECT().ClearBootstrap(mock.Anything, guestProject, guestName).Return(nil).Once()

	fixture.reaper.sweep(t.Context())

	require.Zero(t, store.Len(), "the next tick withdraws what the failed one left")
}

func TestReaperDropsTheRecordOfADeletedInstance(t *testing.T) {
	const seededID nonce.NonceID = "5e6f7a8b9c0d1e2f"

	store := memory.New()
	fixture := newReaperFixture(t, store, store)
	seed(t, store, boundRecord(seededID, time.Now().Add(-time.Minute), false))

	// The instance took its configuration key with it, so there is nothing to
	// clear. A ClearBootstrap call here would fail this test.
	fixture.reader.EXPECT().ReadInstanceByUUID(mock.Anything, guestUUID, guestProject).
		Return(attestor.InstanceRecord{}, attestor.ErrInstanceNotFound).Once()

	fixture.reaper.sweep(t.Context())

	require.Zero(t, store.Len())
	require.Contains(t, fixture.logs.String(), "its instance no longer exists")
}

func TestReaperKeepsSweepingUntilItsContextIsDone(t *testing.T) {
	const seededID nonce.NonceID = "6f7a8b9c0d1e2f3a"

	store := memory.New()
	reader := attestormocks.NewMockInstanceReader(t)
	writer := noncemocks.NewMockBootstrapWriter(t)
	logs := &bytes.Buffer{}

	reaper, err := NewReaper(ReaperConfig{
		Reader:     reader,
		Expired:    store,
		Withdrawer: nonce.NewMinter(store, writer),
		Logger:     slog.New(slog.NewTextHandler(logs, nil)),
		Interval:   time.Millisecond,
		Timeout:    testCompensationTimeout,
	})
	require.NoError(t, err)

	seed(t, store, boundRecord(seededID, time.Now().Add(-time.Minute), false))
	reader.EXPECT().ReadInstanceByUUID(mock.Anything, guestUUID, guestProject).
		Return(liveRecord(), nil).Once()
	writer.EXPECT().ClearBootstrap(mock.Anything, guestProject, guestName).Return(nil).Once()

	ctx, cancel := context.WithCancel(t.Context())
	stopped := make(chan struct{})

	go func() {
		defer close(stopped)

		reaper.Run(ctx)
	}()

	require.Eventually(t, func() bool { return store.Len() == 0 }, time.Second, time.Millisecond,
		"the ticker withdrew the expired record without being driven by the test")

	cancel()

	select {
	case <-stopped:
	case <-time.After(time.Second):
		require.Fail(t, "the reaper did not stop with its context")
	}

	require.Contains(t, logs.String(), "expired nonce reaper stopped")
}

func TestLoadMintTokenRefusesAnAbsentOrShortToken(t *testing.T) {
	directory := t.TempDir()

	write := func(t *testing.T, name string, content string) string {
		t.Helper()

		path := filepath.Join(directory, name)
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

		return path
	}

	t.Run("an absent token file", func(t *testing.T) {
		_, err := loadMintToken(filepath.Join(directory, "missing"))
		require.ErrorIs(t, err, os.ErrNotExist)
	})

	t.Run("an empty token file", func(t *testing.T) {
		_, err := loadMintToken(write(t, "empty", "\n"))
		require.ErrorContains(t, err, "requires at least 32")
	})

	t.Run("a token one character short", func(t *testing.T) {
		short := strings.Repeat("a", minMintTokenLength-1)

		_, err := loadMintToken(write(t, "short", short))
		require.ErrorContains(t, err, "requires at least 32")
		require.NotContains(t, err.Error(), short, "a refused token never appears in the error")
	})

	t.Run("a token of exactly the minimum length", func(t *testing.T) {
		// The trailing newline a shell redirect leaves behind is not part of the
		// token, so a token written with `printf` and one written with `echo`
		// authenticate the same caller.
		digest, err := loadMintToken(write(t, "exact", mintToken+"\n"))
		require.NoError(t, err)
		require.Equal(t, sha256.Sum256([]byte(mintToken)), digest)
	})
}

func TestParseOptionsRequiresAMintTokenFile(t *testing.T) {
	empty := func(string) (string, bool) { return "", false }

	t.Run("without the flag", func(t *testing.T) {
		_, err := parseOptions(brokerArgs(""), empty)
		require.ErrorContains(t, err, "-mint-token-file is required")
	})

	t.Run("with the flag", func(t *testing.T) {
		opts, err := parseOptions(brokerArgs("/run/secrets/mint-token"), empty)
		require.NoError(t, err)
		require.Equal(t, "/run/secrets/mint-token", opts.MintTokenPath)

		// An operator who never mentions a maximum gets the default TTL as the
		// ceiling, so an unrequested ttl_seconds and an absent one agree.
		require.Equal(t, opts.NonceTTL, opts.MaxNonceTTL)
		require.Positive(t, opts.ReapInterval)
		require.Positive(t, opts.ReapTimeout)
		require.Positive(t, opts.ReapGrace)
	})

	t.Run("with a maximum below the default TTL", func(t *testing.T) {
		// A ceiling under the default would refuse nothing while granting more
		// than it admits to, because a request that omits ttl_seconds still gets
		// the process TTL.
		_, err := parseOptions(
			append(brokerArgs("/run/secrets/mint-token"), "-nonce-ttl", "10m", "-max-nonce-ttl", "1m"), empty)
		require.ErrorContains(t, err, "-max-nonce-ttl must not be shorter than -nonce-ttl")
	})
}

// brokerArgs is a complete, otherwise valid broker command line. tokenPath is
// omitted from it when empty, which is the deployment this service must refuse.
func brokerArgs(tokenPath string) []string {
	args := []string{
		"-tls-cert", "/tls/broker.crt",
		"-tls-key", "/tls/broker.key",
		"-advertise-url", "https://broker.invalid:8443",
		"-incus-url", "https://incus.invalid:8443",
		"-incus-server-fingerprint", "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
		"-attestor-cert", "/tls/attestor.crt",
		"-attestor-key", "/tls/attestor.key",
		"-bootstrap-cert", "/tls/bootstrap.crt",
		"-bootstrap-key", "/tls/bootstrap.key",
		"-project", "spike-spiffe",
		"-broker-socket", testBrokerSocket,
		"-workload-api-socket", testWorkloadAPISocket,
		"-agent-spiffe-id", testAgentSPIFFEID,
	}
	if tokenPath != "" {
		args = append(args, "-mint-token-file", tokenPath)
	}

	return args
}

func TestMintOverHTTPRefusesACallerWithoutTheToken(t *testing.T) {
	// The recorder tests exercise the handler; this one proves the same refusal
	// over a real connection, because the operator harness presents its token as
	// a header on the wire and nothing else.
	fixture := newFixture(t, memory.New())

	server := httptest.NewServer(fixture.service.Handler())
	defer server.Close()

	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+mintPath,
		strings.NewReader(`{"instance_uuid":"`+string(guestUUID)+`"}`))
	require.NoError(t, err)

	response, err := server.Client().Do(request)
	require.NoError(t, err)

	defer func() {
		require.NoError(t, response.Body.Close())
	}()

	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)

	require.Equal(t, http.StatusUnauthorized, response.StatusCode, string(body))
	require.JSONEq(t, `{"error":"`+codeUnauthorized+`"}`, string(body))
	require.Equal(t, bearerChallenge, response.Header.Get(headerAuthenticate))

	fixture.reader.AssertNotCalled(t, "ReadInstanceByUUID")
}

func TestReaperKeepsANonceInsideItsGracePeriod(t *testing.T) {
	const (
		freshID nonce.NonceID = "7a8b9c0d1e2f3a4b"
		staleID nonce.NonceID = "8b9c0d1e2f3a4b5c"
	)

	store := memory.New()
	reader := attestormocks.NewMockInstanceReader(t)
	writer := noncemocks.NewMockBootstrapWriter(t)
	logs := &bytes.Buffer{}

	reaper, err := NewReaper(ReaperConfig{
		Reader:     reader,
		Expired:    store,
		Withdrawer: nonce.NewMinter(store, writer),
		Logger:     slog.New(slog.NewTextHandler(logs, nil)),
		Interval:   time.Minute,
		Timeout:    testCompensationTimeout,
		Grace:      time.Minute,
	})
	require.NoError(t, err)

	// One nonce expired ten seconds ago and one an hour ago. Only the second is
	// past the grace period, and the first must keep answering 409 rather than
	// becoming an unknown nonce moments after it stopped working.
	seed(t, store, boundRecord(freshID, time.Now().Add(-10*time.Second), false))
	seed(t, store, boundRecord(staleID, time.Now().Add(-time.Hour), false))

	reader.EXPECT().ReadInstanceByUUID(mock.Anything, guestUUID, guestProject).
		Return(liveRecord(), nil).Once()
	writer.EXPECT().ClearBootstrap(mock.Anything, guestProject, guestName).Return(nil).Once()

	reaper.sweep(t.Context())

	_, err = store.Get(t.Context(), freshID)
	require.NoError(t, err, "a nonce inside its grace period keeps its record")

	_, err = store.Get(t.Context(), staleID)
	require.ErrorIs(t, err, nonce.ErrNonceNotFound, "a nonce past its grace period is withdrawn")

	require.Contains(t, logs.String(), string(staleID))
	require.NotContains(t, logs.String(), string(freshID))
}

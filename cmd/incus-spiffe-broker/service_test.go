package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/componere/incusos-spire/internal/attestor"
	attestormocks "github.com/componere/incusos-spire/internal/attestor/mocks"
	"github.com/componere/incusos-spire/internal/nonce"
	"github.com/componere/incusos-spire/internal/nonce/memory"
	noncemocks "github.com/componere/incusos-spire/internal/nonce/mocks"
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

// fixture is one wired service plus the doubles behind it.
type fixture struct {
	// reader is the read-only Incus path.
	reader *attestormocks.MockInstanceReader
	// writer is the bootstrap configuration writer.
	writer *noncemocks.MockBootstrapWriter
	// store is the nonce store the minter and the service share.
	store nonce.Store
	// service is the subject under test.
	service *Service
	// logs captures everything the service logged.
	logs *bytes.Buffer
}

// newFixture wires a service over store with mocked Incus adapters and the real
// nonce lifecycle and selector cores. The cores are real on purpose: the
// contract under test is the composition, not a restatement of it.
func newFixture(t *testing.T, store nonce.Store) *fixture {
	t.Helper()

	reader := attestormocks.NewMockInstanceReader(t)
	writer := noncemocks.NewMockBootstrapWriter(t)
	logs := &bytes.Buffer{}

	service, err := NewService(ServiceConfig{
		Reader:              reader,
		Bindings:            store,
		Minter:              nonce.NewMinter(store, writer, nonce.WithTTL(time.Minute)),
		Deriver:             attestor.NewDeriver(reader),
		Logger:              slog.New(slog.NewTextHandler(logs, nil)),
		MintTokenDigest:     sha256.Sum256([]byte(mintToken)),
		MaxNonceTTL:         testMaxNonceTTL,
		CompensationTimeout: testCompensationTimeout,
	})
	require.NoError(t, err)

	return &fixture{reader: reader, writer: writer, store: store, service: service, logs: logs}
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

	var redeemed redeemResponse
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &redeemed))
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
			wantStatus: http.StatusConflict,
			wantCode:   codeConflict,
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

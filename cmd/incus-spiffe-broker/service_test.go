package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
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
		Reader:   reader,
		Bindings: store,
		Minter:   nonce.NewMinter(store, writer, nonce.WithTTL(time.Minute)),
		Deriver:  attestor.NewDeriver(reader),
		Logger:   slog.New(slog.NewTextHandler(logs, nil)),
	})
	require.NoError(t, err)

	return &fixture{reader: reader, writer: writer, store: store, service: service, logs: logs}
}

// post sends one JSON body to path and returns the recorded answer.
func (f *fixture) post(t *testing.T, path string, body string) *httptest.ResponseRecorder {
	t.Helper()

	return f.do(t, http.MethodPost, path, body)
}

// do sends one request with an arbitrary method and returns the recorded answer.
func (f *fixture) do(t *testing.T, method string, path string, body string) *httptest.ResponseRecorder {
	t.Helper()

	request := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
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

func TestRedeemIgnoresCallerSuppliedInstanceUUID(t *testing.T) {
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

	fixture.writer.EXPECT().ClearBootstrap(mock.Anything, guestProject, guestName).Return(nil).Once()

	// A hostile guest presents its own valid nonce while claiming another
	// instance. The claim is decoded and discarded: only the bound UUID is
	// resolved. Any read for otherUUID would fail this test, because the mock
	// has no expectation for it.
	response := fixture.post(t, redeemPath,
		`{"nonce_id":"`+string(id)+`","nonce":"`+secret+
			`","instance_uuid":"`+string(otherUUID)+`","project":"other-project"}`)

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

// roundTrip posts body to one endpoint of a live test server.
func roundTrip(t *testing.T, server *httptest.Server, path string, body string) answer {
	t.Helper()

	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+path, strings.NewReader(body))
	require.NoError(t, err)

	response, err := server.Client().Do(request)
	require.NoError(t, err)

	defer func() {
		require.NoError(t, response.Body.Close())
	}()

	payload, err := io.ReadAll(response.Body)
	require.NoError(t, err)

	return answer{status: response.StatusCode, body: string(payload)}
}

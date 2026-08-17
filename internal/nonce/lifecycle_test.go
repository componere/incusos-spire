package nonce_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/componere/incusos-spire/internal/attestor"
	"github.com/componere/incusos-spire/internal/nonce"
	"github.com/componere/incusos-spire/internal/nonce/memory"
	"github.com/componere/incusos-spire/internal/nonce/mocks"
)

const (
	testProject     attestor.ProjectName    = "spike-spiffe"
	testName        attestor.InstanceName   = "spike-guest-a"
	testUUID        attestor.InstanceUUID   = "e9e6a2a0-d695-42d3-8e8c-92d290bfc7da"
	testGeneration  attestor.GenerationUUID = "74957ed8-19bc-4d23-b76b-763bb6f8bb60"
	otherUUID       attestor.InstanceUUID   = "8143228f-fa57-4c09-bae1-5bf3f227cb89"
	otherGeneration attestor.GenerationUUID = "50dd028f-da77-4f87-83e8-0773c72cbc05"

	testID    nonce.NonceID           = "0123456789abcdef0123456789abcdef"
	testURL   nonce.BrokerURL         = "https://10.115.60.1:8443/bootstrap"
	testPrint nonce.BrokerFingerprint = "822b00ed474a2574d43223cbf34919b76a64946e145ec246aa4ae2e43318afdd"

	testTTL      = 90 * time.Second
	redeemers    = 64
	minSecretHex = 64
)

// fixedNow is the injected clock reading used by every lifecycle test.
func fixedNow() time.Time {
	return time.Date(2026, time.August, 16, 23, 0, 0, 0, time.UTC)
}

// liveRecord is the instance record the read path resolves independently.
func liveRecord() attestor.InstanceRecord {
	return attestor.InstanceRecord{
		UUID:       testUUID,
		Generation: testGeneration,
		Project:    testProject,
		Type:       attestor.InstanceTypeVirtualMachine,
		Status:     attestor.InstanceStatusRunning,
		Name:       testName,
	}
}

// boundRecord is a stored nonce record bound to [liveRecord].
func boundRecord() nonce.Record {
	return nonce.Record{
		ID:         testID,
		Hash:       nonce.HashSecret(nonce.NewSecret("presented")),
		Instance:   testUUID,
		Generation: testGeneration,
		Project:    testProject,
		ExpiresAt:  fixedNow().Add(testTTL),
		Used:       true,
	}
}

// newMinter builds a [nonce.Minter] over mock ports with a pinned clock and a
// pinned nonce ID.
func newMinter(t *testing.T) (*nonce.Minter, *mocks.MockStore, *mocks.MockBootstrapWriter) {
	t.Helper()

	store := mocks.NewMockStore(t)
	writer := mocks.NewMockBootstrapWriter(t)
	minter := nonce.NewMinter(store, writer,
		nonce.WithClock(fixedNow),
		nonce.WithTTL(testTTL),
		nonce.WithBroker(testURL, testPrint),
		nonce.WithIDGenerator(func() (nonce.NonceID, error) { return testID, nil }),
	)

	return minter, store, writer
}

func TestMintStoresRecordBeforeWritingPayload(t *testing.T) {
	t.Parallel()

	minter, store, writer := newMinter(t)

	var (
		calls   []string
		stored  nonce.Record
		payload string
	)

	store.EXPECT().Put(mock.Anything, mock.Anything).
		Run(func(_ context.Context, record nonce.Record) {
			calls = append(calls, "put")
			stored = record
		}).Return(nil).Once()
	writer.EXPECT().WriteBootstrap(mock.Anything, testProject, testName, mock.Anything).
		Run(func(_ context.Context, _ attestor.ProjectName, _ attestor.InstanceName, written string) {
			calls = append(calls, "write")
			payload = written
		}).Return(nil).Once()

	issued, err := minter.Mint(t.Context(), testProject, testName, testUUID, testGeneration)
	require.NoError(t, err)

	require.Equal(t, []string{"put", "write"}, calls, "the record must be stored before the payload is written")
	require.Equal(t, testID, issued.ID)
	require.Equal(t, fixedNow().Add(testTTL), issued.ExpiresAt)
	require.GreaterOrEqual(t, len(issued.Secret.Reveal()), minSecretHex, "secret must carry at least 256 bits")

	require.Equal(t, testID, stored.ID)
	require.Equal(t, testUUID, stored.Instance)
	require.Equal(t, testGeneration, stored.Generation)
	require.Equal(t, testProject, stored.Project)
	require.Equal(t, fixedNow().Add(testTTL), stored.ExpiresAt)
	require.False(t, stored.Used)
	require.Equal(t, nonce.HashSecret(issued.Secret), stored.Hash, "the store holds only the hash")
	require.NotContains(t, string(stored.Hash), issued.Secret.Reveal())

	fields := map[string]string{}
	require.NoError(t, json.Unmarshal([]byte(payload), &fields))
	require.Equal(t, map[string]string{
		"nonce":              issued.Secret.Reveal(),
		"nonce_id":           string(testID),
		"broker_url":         string(testURL),
		"broker_fingerprint": string(testPrint),
	}, fields)
	require.Equal(t,
		[]int{0, 1, 2, 3},
		fieldOrder(payload, "nonce", "nonce_id", "broker_url", "broker_fingerprint"),
		"payload field order must be deterministic",
	)
}

// fieldOrder ranks the JSON keys by the position they occupy in payload.
func fieldOrder(payload string, keys ...string) []int {
	positions := make([]int, 0, len(keys))
	for _, key := range keys {
		positions = append(positions, strings.Index(payload, `"`+key+`":`))
	}

	ranks := make([]int, len(positions))
	for i, own := range positions {
		for _, other := range positions {
			if other < own {
				ranks[i]++
			}
		}
	}

	return ranks
}

func TestMintDeletesRecordWhenWriteFails(t *testing.T) {
	t.Parallel()

	minter, store, writer := newMinter(t)
	writeFailure := errors.New("incus: 403 forbidden")

	store.EXPECT().Put(mock.Anything, mock.Anything).Return(nil).Once()
	writer.EXPECT().WriteBootstrap(mock.Anything, testProject, testName, mock.Anything).
		Return(writeFailure).Once()
	store.EXPECT().Delete(mock.Anything, testID).Return(nil).Once()

	issued, err := minter.Mint(t.Context(), testProject, testName, testUUID, testGeneration)
	require.ErrorIs(t, err, nonce.ErrWriterUnavailable)
	require.ErrorIs(t, err, writeFailure)
	require.NotErrorIs(t, err, nonce.ErrStoreUnavailable)
	require.True(t, issued.Secret.IsZero(), "a failed mint hands back no secret")
}

func TestMintReportsDeleteFailureAlongsideWriteFailure(t *testing.T) {
	t.Parallel()

	minter, store, writer := newMinter(t)

	store.EXPECT().Put(mock.Anything, mock.Anything).Return(nil).Once()
	writer.EXPECT().WriteBootstrap(mock.Anything, testProject, testName, mock.Anything).
		Return(errors.New("incus: connection reset")).Once()
	store.EXPECT().Delete(mock.Anything, testID).Return(errors.New("store: closed")).Once()

	_, err := minter.Mint(t.Context(), testProject, testName, testUUID, testGeneration)
	require.ErrorIs(t, err, nonce.ErrWriterUnavailable)
	require.ErrorIs(t, err, nonce.ErrStoreUnavailable)
}

func TestMintDoesNotWriteWhenStoreFails(t *testing.T) {
	t.Parallel()

	minter, store, writer := newMinter(t)
	store.EXPECT().Put(mock.Anything, mock.Anything).Return(errors.New("store: disk full")).Once()

	_, err := minter.Mint(t.Context(), testProject, testName, testUUID, testGeneration)
	require.ErrorIs(t, err, nonce.ErrStoreUnavailable)
	writer.AssertNotCalled(t, "WriteBootstrap", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestMintRejectsIncompleteTarget(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		name       attestor.InstanceName
		uuid       attestor.InstanceUUID
		generation attestor.GenerationUUID
	}{
		"missing name":       {name: "", uuid: testUUID, generation: testGeneration},
		"missing uuid":       {name: testName, uuid: "", generation: testGeneration},
		"missing generation": {name: testName, uuid: testUUID, generation: ""},
	}

	for title, test := range tests {
		t.Run(title, func(t *testing.T) {
			t.Parallel()

			minter, store, writer := newMinter(t)

			_, err := minter.Mint(t.Context(), testProject, test.name, test.uuid, test.generation)
			require.Error(t, err)
			store.AssertNotCalled(t, "Put", mock.Anything, mock.Anything)
			writer.AssertNotCalled(t, "WriteBootstrap", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

func TestRedeemConsumesWithHashAndInjectedClock(t *testing.T) {
	t.Parallel()

	minter, store, _ := newMinter(t)
	secret := nonce.NewSecret("presented")

	store.EXPECT().
		ConsumeOnce(mock.Anything, testID, nonce.HashSecret(secret), fixedNow()).
		Return(boundRecord(), nil).Once()

	record, err := minter.Redeem(t.Context(), testID, secret, liveRecord())
	require.NoError(t, err)
	require.Equal(t, boundRecord(), record)
	require.True(t, record.Used, "the consume step commits used before the caller clears the key")
}

func TestRedeemFailures(t *testing.T) {
	t.Parallel()

	backendFailure := errors.New("store: connection reset")

	tests := map[string]struct {
		id       nonce.NonceID
		secret   nonce.Secret
		consumed nonce.Record
		storeErr error
		expected error
		consumes bool
	}{
		"empty id": {
			id:       "",
			secret:   nonce.NewSecret("presented"),
			expected: nonce.ErrNonceNotFound,
		},
		"empty secret": {
			id:       testID,
			secret:   nonce.Secret{},
			expected: nonce.ErrSecretMismatch,
		},
		"unknown nonce": {
			id:       testID,
			secret:   nonce.NewSecret("presented"),
			storeErr: fmt.Errorf("%w: id %s", nonce.ErrNonceNotFound, testID),
			expected: nonce.ErrNonceNotFound,
			consumes: true,
		},
		"expired nonce": {
			id:       testID,
			secret:   nonce.NewSecret("presented"),
			storeErr: fmt.Errorf("%w: id %s", nonce.ErrNonceExpired, testID),
			expected: nonce.ErrNonceExpired,
			consumes: true,
		},
		"already used nonce": {
			id:       testID,
			secret:   nonce.NewSecret("presented"),
			storeErr: fmt.Errorf("%w: id %s", nonce.ErrNonceAlreadyUsed, testID),
			expected: nonce.ErrNonceAlreadyUsed,
			consumes: true,
		},
		"wrong secret": {
			id:       testID,
			secret:   nonce.NewSecret("guessed"),
			storeErr: fmt.Errorf("%w: id %s", nonce.ErrSecretMismatch, testID),
			expected: nonce.ErrSecretMismatch,
			consumes: true,
		},
		"backend fault": {
			id:       testID,
			secret:   nonce.NewSecret("presented"),
			storeErr: backendFailure,
			expected: nonce.ErrStoreUnavailable,
			consumes: true,
		},
		"bound to another instance": {
			id:     testID,
			secret: nonce.NewSecret("presented"),
			consumed: nonce.Record{
				ID: testID, Instance: otherUUID, Generation: testGeneration, Used: true,
			},
			expected: nonce.ErrInstanceMismatch,
			consumes: true,
		},
		"generation changed by restore": {
			id:     testID,
			secret: nonce.NewSecret("presented"),
			consumed: nonce.Record{
				ID: testID, Instance: testUUID, Generation: otherGeneration, Used: true,
			},
			expected: nonce.ErrGenerationChanged,
			consumes: true,
		},
	}

	for title, test := range tests {
		t.Run(title, func(t *testing.T) {
			t.Parallel()

			minter, store, _ := newMinter(t)
			if test.consumes {
				store.EXPECT().
					ConsumeOnce(mock.Anything, test.id, nonce.HashSecret(test.secret), fixedNow()).
					Return(test.consumed, test.storeErr).Once()
			}

			record, err := minter.Redeem(t.Context(), test.id, test.secret, liveRecord())
			require.ErrorIs(t, err, test.expected)
			require.Equal(t, nonce.Record{}, record, "a rejected redemption returns no record")

			if !test.secret.IsZero() {
				require.NotContains(t, err.Error(), test.secret.Reveal(), "no error may quote a secret")
			}
		})
	}
}

func TestClearWrapsWriterFailure(t *testing.T) {
	t.Parallel()

	minter, _, writer := newMinter(t)
	writer.EXPECT().ClearBootstrap(mock.Anything, testProject, testName).Return(nil).Once()
	require.NoError(t, minter.Clear(t.Context(), testProject, testName))

	failing, _, failingWriter := newMinter(t)
	failingWriter.EXPECT().ClearBootstrap(mock.Anything, testProject, testName).
		Return(errors.New("incus: 500")).Once()
	require.ErrorIs(t, failing.Clear(t.Context(), testProject, testName), nonce.ErrWriterUnavailable)
}

func TestMintThenRedeemOnceOverMemoryStore(t *testing.T) {
	t.Parallel()

	store := memory.New()
	writer := mocks.NewMockBootstrapWriter(t)
	writer.EXPECT().WriteBootstrap(mock.Anything, testProject, testName, mock.Anything).Return(nil).Once()
	writer.EXPECT().ClearBootstrap(mock.Anything, testProject, testName).Return(nil).Once()

	minter := nonce.NewMinter(store, writer,
		nonce.WithClock(fixedNow),
		nonce.WithTTL(testTTL),
		nonce.WithBroker(testURL, testPrint),
	)

	issued, err := minter.Mint(t.Context(), testProject, testName, testUUID, testGeneration)
	require.NoError(t, err)

	record, err := minter.Redeem(t.Context(), issued.ID, issued.Secret, liveRecord())
	require.NoError(t, err)
	require.True(t, record.Used)
	require.NoError(t, minter.Clear(t.Context(), testProject, testName))

	_, err = minter.Redeem(t.Context(), issued.ID, issued.Secret, liveRecord())
	require.ErrorIs(t, err, nonce.ErrNonceAlreadyUsed)
}

func TestRedeemExpiryOverMemoryStore(t *testing.T) {
	t.Parallel()

	store := memory.New()
	writer := mocks.NewMockBootstrapWriter(t)
	writer.EXPECT().WriteBootstrap(mock.Anything, testProject, testName, mock.Anything).Return(nil).Once()

	minter := nonce.NewMinter(store, writer, nonce.WithClock(fixedNow), nonce.WithTTL(testTTL))
	issued, err := minter.Mint(t.Context(), testProject, testName, testUUID, testGeneration)
	require.NoError(t, err)

	late := nonce.NewMinter(store, writer,
		nonce.WithClock(func() time.Time { return fixedNow().Add(testTTL) }),
		nonce.WithTTL(testTTL),
	)

	_, err = late.Redeem(t.Context(), issued.ID, issued.Secret, liveRecord())
	require.ErrorIs(t, err, nonce.ErrNonceExpired, "expiry is inclusive at ExpiresAt")
}

func TestConcurrentRedeemYieldsExactlyOneSuccess(t *testing.T) {
	t.Parallel()

	store := memory.New()
	writer := mocks.NewMockBootstrapWriter(t)
	writer.EXPECT().WriteBootstrap(mock.Anything, testProject, testName, mock.Anything).Return(nil).Once()

	minter := nonce.NewMinter(store, writer, nonce.WithClock(fixedNow), nonce.WithTTL(testTTL))
	issued, err := minter.Mint(t.Context(), testProject, testName, testUUID, testGeneration)
	require.NoError(t, err)

	var (
		successes atomic.Int64
		reuses    atomic.Int64
		others    atomic.Int64
		start     = make(chan struct{})
		wait      sync.WaitGroup
	)

	ctx := t.Context()
	live := liveRecord()

	wait.Add(redeemers)
	for range redeemers {
		go func() {
			defer wait.Done()

			<-start

			switch _, redeemErr := minter.Redeem(ctx, issued.ID, issued.Secret, live); {
			case redeemErr == nil:
				successes.Add(1)
			case errors.Is(redeemErr, nonce.ErrNonceAlreadyUsed):
				reuses.Add(1)
			default:
				others.Add(1)
			}
		}()
	}

	close(start)
	wait.Wait()

	require.Equal(t, int64(1), successes.Load(), "exactly one concurrent redemption may win")
	require.Equal(t, int64(redeemers-1), reuses.Load(), "every loser must be rejected as already used")
	require.Zero(t, others.Load())
}

func TestSecretNeverRevealsMaterialWhenFormatted(t *testing.T) {
	t.Parallel()

	const material = "3f1c7b9e0a2d4c6f8091a2b3c4d5e6f7"

	secret := nonce.NewSecret(material)
	payload := nonce.Payload{
		Secret:            secret,
		NonceID:           testID,
		BrokerURL:         testURL,
		BrokerFingerprint: testPrint,
	}

	rendered := []string{
		fmt.Sprintf("%v", secret),
		fmt.Sprintf("%s", secret),
		fmt.Sprintf("%q", secret),
		fmt.Sprintf("%#v", secret),
		fmt.Sprintf("%d", secret),
		fmt.Sprintf("%x", secret),
		fmt.Sprintf("%+v", struct{ Secret nonce.Secret }{Secret: secret}),
		fmt.Sprint(secret),
		fmt.Sprintf("%v", &secret),
		secret.String(),
		secret.GoString(),
		secret.LogValue().String(),
		fmt.Sprintf("%v", nonce.Issued{ID: testID, Secret: secret}),
		fmt.Sprintf("%#v", payload),
		fmt.Errorf("wrapped %v: %w", secret, nonce.ErrSecretMismatch).Error(),
	}
	for _, text := range rendered {
		require.NotContains(t, text, material)
		require.Contains(t, text, nonce.RedactedSecret)
	}

	var logged bytes.Buffer

	logger := slog.New(slog.NewJSONHandler(&logged, nil))
	logger.Info(
		"redeeming",
		slog.Any("secret", secret),
		slog.Any("payload", payload),
		slog.String("id", string(testID)),
	)
	require.NotContains(t, logged.String(), material)
	require.Contains(t, logged.String(), nonce.RedactedSecret)
	require.Contains(t, logged.String(), string(testID))

	encoded, err := json.Marshal(payload)
	require.NoError(t, err)
	require.Contains(t, string(encoded), material, "the payload is the one deliberate reveal")
	require.Equal(t, material, secret.Reveal())
}

func TestRecordHelpers(t *testing.T) {
	t.Parallel()

	record := boundRecord()
	require.True(t, record.MatchesHash(nonce.HashSecret(nonce.NewSecret("presented"))))
	require.False(t, record.MatchesHash(nonce.HashSecret(nonce.NewSecret("guessed"))))
	require.False(t, record.IsExpired(record.ExpiresAt.Add(-time.Nanosecond)))
	require.True(t, record.IsExpired(record.ExpiresAt), "expiry is inclusive")
	require.True(t, record.IsExpired(record.ExpiresAt.Add(time.Nanosecond)))
}

func TestMinterRejectsWeakOptions(t *testing.T) {
	t.Parallel()

	store := mocks.NewMockStore(t)
	writer := mocks.NewMockBootstrapWriter(t)

	store.EXPECT().Put(mock.Anything, mock.Anything).Return(nil).Once()
	writer.EXPECT().WriteBootstrap(mock.Anything, testProject, testName, mock.Anything).Return(nil).Once()

	minter := nonce.NewMinter(store, writer,
		nil,
		nonce.WithClock(nil),
		nonce.WithIDGenerator(nil),
		nonce.WithTTL(-time.Hour),
		nonce.WithSecretBytes(1),
	)

	issued, err := minter.Mint(t.Context(), testProject, testName, testUUID, testGeneration)
	require.NoError(t, err)
	require.NotEmpty(t, issued.ID, "a nil id generator falls back to the random default")
	require.GreaterOrEqual(t, len(issued.Secret.Reveal()), minSecretHex, "the entropy floor is not negotiable")
	require.True(t, issued.ExpiresAt.After(time.Now()), "a non-positive ttl cannot mint an expired nonce")
}

func TestNewMinterRequiresPorts(t *testing.T) {
	t.Parallel()

	require.Panics(t, func() { nonce.NewMinter(nil, mocks.NewMockBootstrapWriter(t)) })
	require.Panics(t, func() { nonce.NewMinter(mocks.NewMockStore(t), nil) })
}

func TestMintAppliesAPerCallTTL(t *testing.T) {
	t.Parallel()

	const requested = 5 * time.Second

	minter, store, writer := newMinter(t)

	var stored nonce.Record

	store.EXPECT().Put(mock.Anything, mock.Anything).
		Run(func(_ context.Context, record nonce.Record) { stored = record }).Return(nil).Once()
	writer.EXPECT().WriteBootstrap(mock.Anything, testProject, testName, mock.Anything).Return(nil).Once()

	issued, err := minter.Mint(t.Context(), testProject, testName, testUUID, testGeneration,
		nonce.WithMintTTL(requested))
	require.NoError(t, err)

	// The per-call option decides this one issuance and nothing else.
	require.Equal(t, fixedNow().Add(requested), issued.ExpiresAt)
	require.Equal(t, fixedNow().Add(requested), stored.ExpiresAt)
}

func TestMintIgnoresAnUnusablePerCallTTL(t *testing.T) {
	t.Parallel()

	tests := map[string]nonce.MintOption{
		"a negative duration": nonce.WithMintTTL(-time.Second),
		"a zero duration":     nonce.WithMintTTL(0),
		"no option at all":    nil,
	}

	for name, option := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			minter, store, writer := newMinter(t)
			store.EXPECT().Put(mock.Anything, mock.Anything).Return(nil).Once()
			writer.EXPECT().WriteBootstrap(mock.Anything, testProject, testName, mock.Anything).Return(nil).Once()

			issued, err := minter.Mint(t.Context(), testProject, testName, testUUID, testGeneration, option)
			require.NoError(t, err)

			// A miscomputed lifetime falls back to the minter's policy rather
			// than minting a nonce that is already expired.
			require.Equal(t, fixedNow().Add(testTTL), issued.ExpiresAt)
		})
	}
}

func TestMintDeletesRecordWhenWriteFailsAndCallerIsGone(t *testing.T) {
	t.Parallel()

	minter, store, writer := newMinter(t)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	store.EXPECT().Put(mock.Anything, mock.Anything).Return(nil).Once()
	writer.EXPECT().WriteBootstrap(mock.Anything, testProject, testName, mock.Anything).
		RunAndReturn(func(_ context.Context, _ attestor.ProjectName, _ attestor.InstanceName, _ string) error {
			// The operator hangs up while the write is in flight, so the write
			// may or may not have landed and the caller's context is dead.
			cancel()

			return errors.New("incus: connection reset")
		}).Once()

	// The compensating delete must run on a live context. A store that refuses a
	// cancelled context would otherwise leave a redeemable record behind.
	store.EXPECT().Delete(mock.Anything, testID).
		RunAndReturn(func(cleanup context.Context, _ nonce.NonceID) error {
			require.NoError(t, cleanup.Err(), "the cleanup context must not inherit the caller's cancellation")

			deadline, ok := cleanup.Deadline()
			require.True(t, ok, "the cleanup context must stay bounded")
			require.WithinDuration(t, time.Now(), deadline, time.Minute)

			return nil
		}).Once()

	_, err := minter.Mint(ctx, testProject, testName, testUUID, testGeneration)
	require.ErrorIs(t, err, nonce.ErrWriterUnavailable)
	require.NotErrorIs(t, err, nonce.ErrStoreUnavailable)
}

func TestRevokeClearsTheKeyBeforeDroppingTheRecord(t *testing.T) {
	t.Parallel()

	minter, store, writer := newMinter(t)

	var calls []string

	unredeemed := boundRecord()
	unredeemed.Used = false

	store.EXPECT().Get(mock.Anything, testID).
		Run(func(_ context.Context, _ nonce.NonceID) { calls = append(calls, "get") }).
		Return(unredeemed, nil).Once()
	writer.EXPECT().ClearBootstrap(mock.Anything, testProject, testName).
		Run(func(_ context.Context, _ attestor.ProjectName, _ attestor.InstanceName) {
			calls = append(calls, "clear")
		}).Return(nil).Once()
	store.EXPECT().Delete(mock.Anything, testID).
		Run(func(_ context.Context, _ nonce.NonceID) { calls = append(calls, "delete") }).
		Return(nil).Once()

	require.NoError(t, minter.Revoke(t.Context(), testID, testProject, testName))
	require.Equal(t, []string{"get", "clear", "delete"}, calls,
		"the record is the only handle on the key, so it outlives a failed clear")
}

func TestRevokeKeepsTheRecordWhenTheClearFails(t *testing.T) {
	t.Parallel()

	minter, store, writer := newMinter(t)
	clearFailure := errors.New("incus: 503 service unavailable")

	unredeemed := boundRecord()
	unredeemed.Used = false

	store.EXPECT().Get(mock.Anything, testID).Return(unredeemed, nil).Once()
	writer.EXPECT().ClearBootstrap(mock.Anything, testProject, testName).Return(clearFailure).Once()

	// No Delete expectation: dropping the record here would strand the secret in
	// the instance configuration with nothing left to retry against.
	err := minter.Revoke(t.Context(), testID, testProject, testName)
	require.ErrorIs(t, err, nonce.ErrWriterUnavailable)
	require.ErrorIs(t, err, clearFailure)
}

func TestWithdrawalRefusesAConsumedNonce(t *testing.T) {
	t.Parallel()

	withdrawals := map[string]func(minter *nonce.Minter) error{
		"revoke": func(minter *nonce.Minter) error {
			return minter.Revoke(t.Context(), testID, testProject, testName)
		},
		"discard": func(minter *nonce.Minter) error {
			return minter.Discard(t.Context(), testID)
		},
	}

	for name, withdraw := range withdrawals {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			minter, store, _ := newMinter(t)
			// boundRecord is already consumed: the redemption path owns the
			// clear for it, so neither a clear nor a delete may happen here.
			store.EXPECT().Get(mock.Anything, testID).Return(boundRecord(), nil).Once()

			require.ErrorIs(t, withdraw(minter), nonce.ErrNonceAlreadyUsed)
		})
	}
}

func TestWithdrawalReportsAnUnknownNonceAndABrokenStore(t *testing.T) {
	t.Parallel()

	t.Run("an unknown nonce", func(t *testing.T) {
		t.Parallel()

		minter, store, _ := newMinter(t)
		store.EXPECT().Get(mock.Anything, testID).Return(nonce.Record{}, nonce.ErrNonceNotFound).Once()

		err := minter.Revoke(t.Context(), testID, testProject, testName)
		require.ErrorIs(t, err, nonce.ErrNonceNotFound)
		require.NotErrorIs(t, err, nonce.ErrStoreUnavailable)
	})

	t.Run("an empty nonce id", func(t *testing.T) {
		t.Parallel()

		minter, _, _ := newMinter(t)

		require.ErrorIs(t, minter.Discard(t.Context(), ""), nonce.ErrNonceNotFound)
	})

	t.Run("a broken store", func(t *testing.T) {
		t.Parallel()

		minter, store, _ := newMinter(t)
		store.EXPECT().Get(mock.Anything, testID).Return(nonce.Record{}, errors.New("store: closed")).Once()

		err := minter.Discard(t.Context(), testID)
		require.ErrorIs(t, err, nonce.ErrStoreUnavailable)
		require.NotErrorIs(t, err, nonce.ErrNonceNotFound)
	})
}

func TestDiscardDropsTheRecordWithoutTouchingTheInstance(t *testing.T) {
	t.Parallel()

	minter, store, _ := newMinter(t)

	unredeemed := boundRecord()
	unredeemed.Used = false

	// No writer expectation at all: the instance this nonce was bound to is
	// gone, so there is no configuration key left to clear.
	store.EXPECT().Get(mock.Anything, testID).Return(unredeemed, nil).Once()
	store.EXPECT().Delete(mock.Anything, testID).Return(nil).Once()

	require.NoError(t, minter.Discard(t.Context(), testID))
}

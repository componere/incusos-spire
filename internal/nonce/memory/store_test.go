package memory_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/componere/incusos-spire/internal/attestor"
	"github.com/componere/incusos-spire/internal/nonce"
	"github.com/componere/incusos-spire/internal/nonce/memory"
)

const (
	storedID   nonce.NonceID           = "0123456789abcdef0123456789abcdef"
	absentID   nonce.NonceID           = "ffffffffffffffffffffffffffffffff"
	boundUUID  attestor.InstanceUUID   = "e9e6a2a0-d695-42d3-8e8c-92d290bfc7da"
	boundGen   attestor.GenerationUUID = "74957ed8-19bc-4d23-b76b-763bb6f8bb60"
	boundProj  attestor.ProjectName    = "spike-spiffe"
	secretText                         = "3f1c7b9e0a2d4c6f8091a2b3c4d5e6f7"
	consumers                          = 128
	storeTTL                           = time.Minute
)

// storeNow is the pinned clock reading every store test consumes against.
func storeNow() time.Time {
	return time.Date(2026, time.August, 16, 23, 0, 0, 0, time.UTC)
}

// storedRecord is an unused record bound to a live instance.
func storedRecord() nonce.Record {
	return nonce.Record{
		ID:         storedID,
		Hash:       nonce.HashSecret(nonce.NewSecret(secretText)),
		Instance:   boundUUID,
		Generation: boundGen,
		Project:    boundProj,
		ExpiresAt:  storeNow().Add(storeTTL),
		Used:       false,
	}
}

// filledStore returns a store holding exactly [storedRecord].
func filledStore(t *testing.T) *memory.Store {
	t.Helper()

	store := memory.New()
	require.NoError(t, store.Put(t.Context(), storedRecord()))

	return store
}

func TestConsumeOnceExactlyOneWinnerUnderConcurrency(t *testing.T) {
	t.Parallel()

	store := filledStore(t)
	hash := nonce.HashSecret(nonce.NewSecret(secretText))

	var (
		successes atomic.Int64
		reuses    atomic.Int64
		others    atomic.Int64
		start     = make(chan struct{})
		wait      sync.WaitGroup
	)

	ctx := t.Context()

	wait.Add(consumers)
	for range consumers {
		go func() {
			defer wait.Done()

			<-start

			switch record, err := store.ConsumeOnce(ctx, storedID, hash, storeNow()); {
			case err == nil:
				if record.Used && record.Instance == boundUUID {
					successes.Add(1)
				}
			case errors.Is(err, nonce.ErrNonceAlreadyUsed):
				reuses.Add(1)
			default:
				others.Add(1)
			}
		}()
	}

	close(start)
	wait.Wait()

	require.Equal(t, int64(1), successes.Load(), "compare-and-set must admit exactly one consumer")
	require.Equal(t, int64(consumers-1), reuses.Load(), "every other consumer must see the nonce as already used")
	require.Zero(t, others.Load())

	record, err := store.Get(ctx, storedID)
	require.NoError(t, err)
	require.True(t, record.Used, "the winning consume is committed")
}

func TestConsumeOnceRejections(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		id       nonce.NonceID
		hash     nonce.NonceHash
		now      time.Time
		expected error
	}{
		"unknown id": {
			id:       absentID,
			hash:     nonce.HashSecret(nonce.NewSecret(secretText)),
			now:      storeNow(),
			expected: nonce.ErrNonceNotFound,
		},
		"wrong secret": {
			id:       storedID,
			hash:     nonce.HashSecret(nonce.NewSecret("guessed")),
			now:      storeNow(),
			expected: nonce.ErrSecretMismatch,
		},
		"expired at expiry instant": {
			id:       storedID,
			hash:     nonce.HashSecret(nonce.NewSecret(secretText)),
			now:      storeNow().Add(storeTTL),
			expected: nonce.ErrNonceExpired,
		},
		"expired after expiry": {
			id:       storedID,
			hash:     nonce.HashSecret(nonce.NewSecret(secretText)),
			now:      storeNow().Add(2 * storeTTL),
			expected: nonce.ErrNonceExpired,
		},
	}

	for title, test := range tests {
		t.Run(title, func(t *testing.T) {
			t.Parallel()

			store := filledStore(t)

			record, err := store.ConsumeOnce(t.Context(), test.id, test.hash, test.now)
			require.ErrorIs(t, err, test.expected)
			require.Equal(t, nonce.Record{}, record)

			stored, getErr := store.Get(t.Context(), storedID)
			require.NoError(t, getErr)
			require.False(t, stored.Used, "a rejected consume must not burn the nonce")
		})
	}
}

func TestConsumeOnceRejectsSecondAttempt(t *testing.T) {
	t.Parallel()

	store := filledStore(t)
	hash := nonce.HashSecret(nonce.NewSecret(secretText))

	first, err := store.ConsumeOnce(t.Context(), storedID, hash, storeNow())
	require.NoError(t, err)
	require.True(t, first.Used)

	_, err = store.ConsumeOnce(t.Context(), storedID, hash, storeNow())
	require.ErrorIs(t, err, nonce.ErrNonceAlreadyUsed)
}

func TestWrongSecretStillLeavesNonceRedeemable(t *testing.T) {
	t.Parallel()

	store := filledStore(t)

	_, err := store.ConsumeOnce(t.Context(), storedID, nonce.HashSecret(nonce.NewSecret("guessed")), storeNow())
	require.ErrorIs(t, err, nonce.ErrSecretMismatch)

	record, err := store.ConsumeOnce(
		t.Context(), storedID, nonce.HashSecret(nonce.NewSecret(secretText)), storeNow(),
	)
	require.NoError(t, err)
	require.True(t, record.Used)
}

func TestPutRefusesDuplicateAndEmptyID(t *testing.T) {
	t.Parallel()

	store := filledStore(t)

	require.Error(t, store.Put(t.Context(), storedRecord()), "a live binding is never overwritten")
	require.Error(t, store.Put(t.Context(), nonce.Record{}))
	require.Equal(t, 1, store.Len())
}

func TestGetAndDeleteReportMissingRecords(t *testing.T) {
	t.Parallel()

	store := filledStore(t)

	_, err := store.Get(t.Context(), absentID)
	require.ErrorIs(t, err, nonce.ErrNonceNotFound)
	require.ErrorIs(t, store.Delete(t.Context(), absentID), nonce.ErrNonceNotFound)

	require.NoError(t, store.Delete(t.Context(), storedID))
	require.Zero(t, store.Len())

	_, err = store.Get(t.Context(), storedID)
	require.ErrorIs(t, err, nonce.ErrNonceNotFound)
}

func TestOperationsHonourCancelledContext(t *testing.T) {
	t.Parallel()

	store := filledStore(t)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	require.ErrorIs(t, store.Put(ctx, storedRecord()), context.Canceled)
	require.ErrorIs(t, store.Delete(ctx, storedID), context.Canceled)

	_, err := store.Get(ctx, storedID)
	require.ErrorIs(t, err, context.Canceled)

	_, err = store.ConsumeOnce(ctx, storedID, nonce.HashSecret(nonce.NewSecret(secretText)), storeNow())
	require.ErrorIs(t, err, context.Canceled)

	record, err := store.Get(t.Context(), storedID)
	require.NoError(t, err)
	require.False(t, record.Used)
}

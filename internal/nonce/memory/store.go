package memory

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/componere/incusos-spire/internal/nonce"
)

// Store keeps nonce records in a map guarded by one mutex. It implements
// [github.com/componere/incusos-spire/internal/nonce.Store].
type Store struct {
	// mu serialises every operation. It is what makes
	// [Store.ConsumeOnce] atomic.
	mu sync.Mutex
	// records holds one entry per outstanding nonce, keyed by nonce ID. It
	// never holds a secret, only its hash.
	records map[nonce.NonceID]nonce.Record
}

// New returns an empty [Store] ready for use.
func New() *Store {
	return &Store{
		mu:      sync.Mutex{},
		records: make(map[nonce.NonceID]nonce.Record),
	}
}

// Put records a freshly minted nonce. A duplicate ID is refused rather than
// overwritten: replacing a live binding would silently revoke a nonce a guest
// may already hold.
func (s *Store) Put(ctx context.Context, record nonce.Record) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("memory: put nonce %s: %w", record.ID, err)
	}

	if record.ID == "" {
		return fmt.Errorf("memory: put nonce: %w", errEmptyID)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.records[record.ID]; exists {
		return fmt.Errorf("memory: put nonce %s: %w", record.ID, errDuplicateID)
	}

	s.records[record.ID] = record

	return nil
}

// ConsumeOnce marks the nonce used and returns it, in one atomic step under the
// store mutex. It succeeds only when the record exists, hash matches its stored
// hash in constant time, the record is unexpired at now, and it was not already
// used. Every rejection leaves the stored record exactly as it was, so a wrong
// secret cannot burn a nonce.
func (s *Store) ConsumeOnce(
	ctx context.Context,
	id nonce.NonceID,
	hash nonce.NonceHash,
	now time.Time,
) (nonce.Record, error) {
	if err := ctx.Err(); err != nil {
		return nonce.Record{}, fmt.Errorf("memory: consume nonce %s: %w", id, err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	record, found := s.records[id]
	if !found {
		return nonce.Record{}, fmt.Errorf("%w: id %s", nonce.ErrNonceNotFound, id)
	}

	if !record.MatchesHash(hash) {
		return nonce.Record{}, fmt.Errorf("%w: id %s", nonce.ErrSecretMismatch, id)
	}

	if record.Used {
		return nonce.Record{}, fmt.Errorf("%w: id %s", nonce.ErrNonceAlreadyUsed, id)
	}

	if record.IsExpired(now) {
		return nonce.Record{}, fmt.Errorf("%w: id %s", nonce.ErrNonceExpired, id)
	}

	record.Used = true
	s.records[id] = record

	return record, nil
}

// Get returns the record for id without consuming it.
func (s *Store) Get(ctx context.Context, id nonce.NonceID) (nonce.Record, error) {
	if err := ctx.Err(); err != nil {
		return nonce.Record{}, fmt.Errorf("memory: get nonce %s: %w", id, err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	record, found := s.records[id]
	if !found {
		return nonce.Record{}, fmt.Errorf("%w: id %s", nonce.ErrNonceNotFound, id)
	}

	return record, nil
}

// ListExpired returns every stored record that is expired at now and was never
// consumed. A consumed record is deliberately withheld: its configuration value
// can no longer redeem, and the record is what makes a replay answer "already
// used" instead of "not found".
//
// The result is sorted by nonce ID so a sweep, and the log it produces, is
// reproducible. Map iteration order would otherwise reshuffle the evidence of
// every reap for no reason.
func (s *Store) ListExpired(ctx context.Context, now time.Time) ([]nonce.Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("memory: list expired nonces: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	expired := make([]nonce.Record, 0, len(s.records))

	for _, record := range s.records {
		if record.Used || !record.IsExpired(now) {
			continue
		}

		expired = append(expired, record)
	}

	slices.SortFunc(expired, func(left nonce.Record, right nonce.Record) int {
		return cmp.Compare(left.ID, right.ID)
	})

	return expired, nil
}

// Delete removes the record for id.
func (s *Store) Delete(ctx context.Context, id nonce.NonceID) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("memory: delete nonce %s: %w", id, err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, found := s.records[id]; !found {
		return fmt.Errorf("%w: id %s", nonce.ErrNonceNotFound, id)
	}

	delete(s.records, id)

	return nil
}

// Len returns the number of stored records. It exists for tests and operator
// inspection.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.records)
}

// storeError is a comparable sentinel for store preconditions. A caller maps
// these onto
// [github.com/componere/incusos-spire/internal/nonce.ErrStoreUnavailable],
// because they report a violated precondition, not a nonce lifecycle outcome.
type storeError string

// Error returns the sentinel's stable message.
func (e storeError) Error() string {
	return string(e)
}

const (
	// errEmptyID is returned when a record carries no nonce ID.
	errEmptyID storeError = "record has no nonce id"
	// errDuplicateID is returned when a nonce ID is already stored.
	errDuplicateID storeError = "nonce id already stored"
)

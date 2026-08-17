// Package memory is the in-process reference adapter for the nonce
// github.com/componere/incusos-spire/internal/nonce.Store port.
//
// A single [sync.Mutex] serialises every operation, which is what makes
// ConsumeOnce a genuine atomic compare-and-set: the existence check, the
// constant-time hash comparison, the expiry check, the already-used check, and
// the Used=true commit all happen while one goroutine holds the lock. Its test
// proves the property that matters, exactly one winner across many concurrent
// redemptions of the same nonce.
//
// # Durability
//
// This store is memory only. Nonces do not survive a broker restart: every
// outstanding binding is lost and each affected guest must be issued a fresh
// nonce. That is acceptable for a nonce whose TTL is measured in minutes, and it
// fails closed, since a lost record can only cause a rejected redemption, never
// an accepted one.
//
// # Why there is no SQLite adapter
//
// The spike's artifact list holds a conditional internal/nonce/sqlite adapter,
// and it is deliberately not built. The requirement under test is atomic single
// use, and a mutex around an in-process map satisfies it completely and
// observably. Durability across a broker restart is the only property SQLite
// would add, and no spike acceptance criterion depends on it. Building the
// persistence adapter before an experiment fixes the storage contract would
// freeze a schema and a transaction shape that nothing has yet exercised. When
// restart survival becomes a requirement, the adapter implements the same port
// with a single-statement conditional UPDATE ... WHERE used = 0 as its
// compare-and-set, and this package stays as the fast test double.
package memory

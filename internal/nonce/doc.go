// Package nonce is the pure one-time bootstrap-nonce lifecycle core for
// binding an Incus guest to its own instance record.
//
// The package performs no I/O. It owns two consumer-owned ports (A1): [Store]
// for nonce persistence with an atomic single-use consume step, and
// [BootstrapWriter] for writing the guest-readable bootstrap payload into the
// instance configuration. Adapters in other packages implement both; this
// package imports only the standard library and the pure
// github.com/componere/incusos-spire/internal/attestor domain vocabulary.
//
// Callers construct a [Minter] with [NewMinter], mint a nonce with
// [Minter.Mint], and redeem it with [Minter.Redeem].
//
// # Secret handling
//
// A nonce secret exists only as a [Secret], whose formatting, [fmt.GoStringer],
// and [log/slog] representations are all redacted. The [Store] never sees the
// secret: it holds a [NonceHash] only. No error returned from this package
// contains secret material, so a caller cannot leak one by logging a failure.
// Only [Secret.Reveal] exposes the material, and only [Payload.MarshalJSON]
// calls it, because the payload is the one place the secret must travel.
//
// # Lifecycle ordering
//
// The ordering of the store and writer calls is load-bearing, not incidental:
//
//   - [Minter.Mint] stores the hashed record before writing the bootstrap
//     payload. A crash between the two leaves an unreadable record with no
//     readable secret, never a readable secret with no record to consume. If
//     the write fails, the record is deleted again.
//   - [Minter.Redeem] commits Used=true through [Store.ConsumeOnce] before the
//     caller clears the bootstrap key with [Minter.Clear]. A crash between
//     those two leaves a harmless consumed value in the instance
//     configuration, never a reusable credential.
//
// # Trust
//
// [Minter.Redeem] never trusts a caller-claimed instance identity. The caller
// passes the live [github.com/componere/incusos-spire/internal/attestor.InstanceRecord]
// that the read path resolved independently, and redemption fails closed when
// the consumed record's instance or generation disagrees with it. A snapshot
// restore replaces volatile.uuid.generation, so an outstanding nonce minted
// before the restore is rejected with [ErrGenerationChanged].
//
// # Residual risk
//
// An unredeemed nonce is a bearer credential. Its only protections are
// per-instance /dev/incus/sock visibility, high entropy, a short TTL, and
// single use. Theft of an unredeemed secret allows impersonation of the bound
// instance until the nonce expires; that is a recorded spike finding (risk
// R10), not something this package can solve.
package nonce

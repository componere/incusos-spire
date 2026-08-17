package nonce

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/componere/incusos-spire/internal/attestor"
)

// RedactedSecret is the fixed text every formatting path of a [Secret] and a
// [Payload] returns instead of secret material.
const RedactedSecret = "nonce-secret(redacted)"

// NonceID is the public identifier of a minted nonce. It carries no secret
// material and is the only nonce coordinate that may appear in a log line, an
// error, or spike evidence.
//
// carry an instance uuid and a generation uuid; a bare nonce.ID would read as
// "which id?" in exactly the code where the distinction matters.
//
//nolint:revive // NonceID keeps the domain term intact at call sites that also
type NonceID string

// NonceHash is the lowercase hexadecimal SHA-256 digest of a nonce secret, as
// produced by [HashSecret]. It is the only nonce representation a [Store] ever
// holds, so a stolen store cannot yield a usable credential.
//
// would invite confusion with the several other hashes this system handles.
//
//nolint:revive // NonceHash names the digest of a nonce secret; nonce.Hash
type NonceHash string

// BrokerURL is the guest-facing URL of the broker bootstrap endpoint that a
// guest contacts to redeem its nonce.
type BrokerURL string

// BrokerFingerprint is the SHA-256 fingerprint of the broker's TLS server
// certificate. The guest pins the broker to this fingerprint, so the bootstrap
// exchange does not depend on a guest-side trust store.
type BrokerFingerprint string

// Secret is the high-entropy nonce value handed to a guest.
//
// The material is unexported and every formatting path is redacted:
// [Secret.Format], [Secret.String], [Secret.GoString], and [Secret.LogValue]
// all render [RedactedSecret]. A Secret therefore cannot leak through any [fmt]
// verb, through [log/slog], or into an error string. [Secret.Reveal] is the
// single deliberate accessor.
type Secret struct {
	// value is the raw secret material. Nothing in this package formats,
	// records, or compares it except [HashSecret] and [Secret.Reveal].
	value string
}

// NewSecret wraps raw secret material presented by a caller, such as the value
// a guest read from its own bootstrap configuration key.
func NewSecret(value string) Secret {
	return Secret{value: value}
}

// String returns [RedactedSecret]. It satisfies [fmt.Stringer] so that %v and
// %s can never print secret material.
func (s Secret) String() string {
	return RedactedSecret
}

// Format writes [RedactedSecret] for every verb. It satisfies [fmt.Formatter],
// which [fmt] consults ahead of [fmt.Stringer] and for verbs such as %d that a
// Stringer does not cover, so no verb can reach the secret material.
func (s Secret) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, RedactedSecret)
}

// GoString returns [RedactedSecret]. It satisfies [fmt.GoStringer] so that %#v
// can never print secret material.
func (s Secret) GoString() string {
	return RedactedSecret
}

// LogValue returns [RedactedSecret] as a [log/slog] value. It satisfies
// [log/slog.LogValuer] so that structured logging can never record secret
// material.
func (s Secret) LogValue() slog.Value {
	return slog.StringValue(RedactedSecret)
}

// Reveal returns the raw secret material. Every call site is a deliberate
// decision to move the secret across a boundary and must be reviewed against
// the secret-handling rules.
func (s Secret) Reveal() string {
	return s.value
}

// IsZero reports whether the secret carries no material. It lets callers reject
// an empty presentation without revealing anything.
func (s Secret) IsZero() bool {
	return s.value == ""
}

// HashSecret returns the lowercase hexadecimal SHA-256 digest of secret. It is
// the only function besides [Secret.Reveal] that touches secret material, and
// it is how a secret becomes storable.
func HashSecret(secret Secret) NonceHash {
	digest := sha256.Sum256([]byte(secret.value))

	return NonceHash(hex.EncodeToString(digest[:]))
}

// Record is the stored state of one minted nonce. It binds the nonce to exactly
// one instance identity plus one generation, and it never holds the secret.
type Record struct {
	// ID is the public nonce identifier presented at redemption.
	ID NonceID
	// Hash is the SHA-256 digest of the secret. It is compared with
	// [Record.MatchesHash], never with a plain equality check.
	Hash NonceHash
	// Instance is the bound volatile.uuid. It is the non-reusable identity
	// anchor and must equal the live record resolved by the read path.
	Instance attestor.InstanceUUID
	// Generation is the bound volatile.uuid.generation. A snapshot restore
	// replaces it, which invalidates this nonce.
	Generation attestor.GenerationUUID
	// Project is the Incus project holding the bound instance.
	Project attestor.ProjectName
	// ExpiresAt is the instant at which the nonce stops being redeemable.
	// Expiry is inclusive, per [Record.IsExpired].
	ExpiresAt time.Time
	// Used reports whether the nonce was already consumed. Only
	// [Store.ConsumeOnce] may set it, and only once.
	Used bool
}

// IsExpired reports whether the nonce is no longer redeemable at now. Expiry is
// inclusive: a nonce is expired at exactly [Record.ExpiresAt].
func (r Record) IsExpired(now time.Time) bool {
	return !now.Before(r.ExpiresAt)
}

// MatchesHash reports whether hash equals the stored hash, compared in constant
// time so that a redemption attempt cannot be turned into a digest oracle.
func (r Record) MatchesHash(hash NonceHash) bool {
	return subtle.ConstantTimeCompare([]byte(r.Hash), []byte(hash)) == 1
}

// Issued is the result of [Minter.Mint]. It is the only value in this package
// that carries a live [Secret], and the caller hands it to nothing but the
// guest-facing bootstrap channel.
type Issued struct {
	// ID is the public identifier the guest presents at redemption.
	ID NonceID
	// Secret is the redacted-by-default nonce material.
	Secret Secret
	// ExpiresAt is the instant at which the nonce stops being redeemable.
	ExpiresAt time.Time
}

// Store is the consumer-owned port for nonce persistence.
//
// Adapters implement it; this package never performs I/O. The port holds hashes
// only, never secrets.
//
// ConsumeOnce carries the single security-critical requirement: it is one
// atomic compare-and-set. Concurrent redemptions of the same nonce must yield
// exactly one success, so the existence check, the hash comparison, the expiry
// check, the already-used check, and the Used=true commit happen in one
// indivisible step. An implementation that reads a record, decides, and writes
// back without holding exclusive access does not satisfy this port.
//
// Implementations classify their failures with the sentinels of this package:
// [ErrNonceNotFound], [ErrNonceExpired], [ErrNonceAlreadyUsed], and
// [ErrSecretMismatch] are lifecycle answers, and anything else is a backend
// fault that the caller maps to [ErrStoreUnavailable].
type Store interface {
	// Put records a freshly minted nonce. It overwrites nothing: an existing ID
	// is a programming error and the implementation reports it as a failure
	// rather than replacing a live binding.
	Put(ctx context.Context, record Record) error
	// ConsumeOnce atomically marks the nonce used and returns it, only if the
	// record exists, hash matches its stored hash, it is unexpired at now, and
	// it was not already used. Otherwise it returns the matching lifecycle
	// sentinel and leaves the record untouched.
	ConsumeOnce(ctx context.Context, id NonceID, hash NonceHash, now time.Time) (Record, error)
	// Get returns the record for id without consuming it. It exists for
	// operator inspection and evidence, never as a redemption path.
	Get(ctx context.Context, id NonceID) (Record, error)
	// ListExpired returns every record that is expired at now and was never
	// consumed: exactly the set whose bootstrap configuration key may still
	// hold a live secret nobody redeemed. It is the reaper's query, so an
	// implementation must not consume, modify, or delete anything, and an
	// empty result is a normal answer rather than [ErrNonceNotFound].
	//
	// Consumed records are excluded on purpose. Their configuration value can
	// no longer redeem, and the record itself is what lets a replay be refused
	// as already used instead of as unknown, so withdrawing it would trade a
	// precise answer for nothing.
	ListExpired(ctx context.Context, now time.Time) ([]Record, error)
	// Delete removes the record for id. Deleting an absent record returns
	// [ErrNonceNotFound].
	Delete(ctx context.Context, id NonceID) error
}

// BootstrapWriter is the consumer-owned port for the guest-readable bootstrap
// configuration key.
//
// The write target is an instance name, not a UUID, and that is forced by the
// deployed authorization model (P5): Incus 7.3 has no fine-grained
// authorization API, so the bootstrap-writer identity is genuinely write-only
// and is denied every read in its project. A UUID-to-name resolution is a read,
// so the writer cannot perform it. The composing service resolves the name
// through the separate read-only identity path and passes it here.
//
// Because an Incus instance name is reusable after delete and recreate (P6),
// the caller MUST re-resolve the name from the UUID immediately before each
// write. A cached name may denote a different instance. The UUID plus
// generation stay the identity anchor; the name is only the write address.
//
// An adapter implementing this port also refuses to write any configuration key
// outside an explicit allowlist. The same credential can technically write
// volatile.uuid and delete instances, so key restriction is the defence in
// depth that authorization cannot provide.
type BootstrapWriter interface {
	// WriteBootstrap sets the bootstrap configuration key on the named instance
	// to payload. payload is the JSON produced by [Payload.MarshalJSON] and
	// contains the nonce secret, so an implementation must never log it.
	WriteBootstrap(ctx context.Context, project attestor.ProjectName, name attestor.InstanceName, payload string) error
	// ClearBootstrap empties the bootstrap configuration key on the named
	// instance. It is called after a redemption commits, and clearing an
	// already-empty key is not an error.
	ClearBootstrap(ctx context.Context, project attestor.ProjectName, name attestor.InstanceName) error
}

// sentinelError is a comparable sentinel used with [errors.Is].
type sentinelError string

// Error returns the sentinel's stable message.
func (e sentinelError) Error() string {
	return string(e)
}

const (
	// ErrNonceNotFound is returned when no record exists for the presented
	// nonce ID, including when the ID is empty. It is also returned by
	// [Store.Delete] for an absent record.
	ErrNonceNotFound sentinelError = "nonce: nonce not found"
	// ErrNonceExpired is returned when the record exists but its TTL elapsed.
	// Expiry is inclusive at [Record.ExpiresAt].
	ErrNonceExpired sentinelError = "nonce: nonce expired"
	// ErrNonceAlreadyUsed is returned when the record was already consumed.
	// Every concurrent redemption of one nonce but the single winner ends here.
	ErrNonceAlreadyUsed sentinelError = "nonce: nonce already used"
	// ErrSecretMismatch is returned when the presented secret hashes to
	// something other than the stored hash, or when the presentation is empty.
	// The error never contains either the secret or a hash.
	//nolint:gosec // G101 false positive: this is a sentinel message, not a credential.
	ErrSecretMismatch sentinelError = "nonce: nonce secret mismatch"
	// ErrInstanceMismatch is returned when the consumed record is bound to a
	// different instance than the live record the read path resolved. This is
	// the wrong-instance case: a guest presenting its own valid nonce while
	// claiming another instance's identity fails here.
	ErrInstanceMismatch sentinelError = "nonce: bound instance mismatch"
	// ErrGenerationChanged is returned when the consumed record's generation
	// differs from the live volatile.uuid.generation. A snapshot restore
	// replaces the generation, so this is the rollback discriminator.
	ErrGenerationChanged sentinelError = "nonce: instance generation changed"
	// ErrStoreUnavailable is returned when the [Store] failed for a reason that
	// is not a lifecycle answer: a backend fault, a cancelled context, or a
	// violated store precondition.
	ErrStoreUnavailable sentinelError = "nonce: nonce store unavailable"
	// ErrWriterUnavailable is returned when the [BootstrapWriter] could not
	// write or clear the bootstrap key.
	ErrWriterUnavailable sentinelError = "nonce: bootstrap writer unavailable"
)

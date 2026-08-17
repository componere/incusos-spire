package nonce

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/componere/incusos-spire/internal/attestor"
)

const (
	// defaultTTL is the default nonce lifetime. A bootstrap exchange takes
	// seconds, so the window stays short by default.
	defaultTTL = 2 * time.Minute
	// defaultSecretBytes is the default secret length in bytes drawn from
	// [crypto/rand]. It is also the enforced floor: an unredeemed nonce is a
	// bearer credential, so 256 bits of entropy is the minimum.
	defaultSecretBytes = 32
	// idBytes is the length in bytes of a generated [NonceID] before hex
	// encoding. The ID is a public correlation handle, not a secret.
	idBytes = 16
)

// Payload is the JSON document written to the guest-readable bootstrap
// configuration key. It is the only carrier that moves a [Secret] outside this
// package.
//
// Marshalling produces exactly four fields, in this order:
//
//	{"nonce":"<secret>","nonce_id":"<id>","broker_url":"<url>","broker_fingerprint":"<sha256>"}
//
// Formatting a Payload with [fmt] or [log/slog] yields [RedactedSecret] for the
// whole value, so only a deliberate [Payload.MarshalJSON] call reveals the
// secret.
type Payload struct {
	// Secret is the nonce material the guest presents back to the broker.
	Secret Secret
	// NonceID is the public identifier the guest presents alongside the secret.
	NonceID NonceID
	// BrokerURL is the endpoint the guest contacts to redeem the nonce.
	BrokerURL BrokerURL
	// BrokerFingerprint is the broker TLS certificate fingerprint the guest
	// pins.
	BrokerFingerprint BrokerFingerprint
}

// MarshalJSON renders the payload with the secret in clear text, because the
// guest must be able to read it. This is the single deliberate reveal of a
// [Secret] in this package; field order is fixed, so the output is
// deterministic.
func (p Payload) MarshalJSON() ([]byte, error) {
	wire := payloadWire{
		Nonce:             p.Secret.Reveal(),
		NonceID:           string(p.NonceID),
		BrokerURL:         string(p.BrokerURL),
		BrokerFingerprint: string(p.BrokerFingerprint),
	}

	encoded, err := json.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("nonce: marshal bootstrap payload for %s: %w", p.NonceID, err)
	}

	return encoded, nil
}

// String returns [RedactedSecret]. It satisfies [fmt.Stringer] so that %v and
// %s on a payload cannot print the secret it carries.
func (p Payload) String() string {
	return RedactedSecret
}

// GoString returns [RedactedSecret]. It satisfies [fmt.GoStringer] so that %#v
// cannot print the secret the payload carries.
func (p Payload) GoString() string {
	return RedactedSecret
}

// LogValue returns [RedactedSecret] as a [log/slog] value. It satisfies
// [log/slog.LogValuer] so that structured logging cannot record the secret the
// payload carries.
func (p Payload) LogValue() slog.Value {
	return slog.StringValue(RedactedSecret)
}

// payloadWire is the on-the-wire field layout of a [Payload]. It exists so the
// tagged, secret-bearing representation cannot be constructed by accident:
// [Payload.MarshalJSON] is the only place that fills it in.
type payloadWire struct {
	// Nonce is the revealed secret material.
	Nonce string `json:"nonce"`
	// NonceID is the public nonce identifier.
	NonceID string `json:"nonce_id"`
	// BrokerURL is the guest-facing broker endpoint.
	BrokerURL string `json:"broker_url"`
	// BrokerFingerprint is the broker TLS certificate fingerprint.
	BrokerFingerprint string `json:"broker_fingerprint"`
}

// Clock returns the current time. It is injected so lifecycle tests are
// deterministic and never sleep.
type Clock func() time.Time

// IDGenerator returns a fresh [NonceID]. It is injected so tests can pin the
// identifier a mint produces.
type IDGenerator func() (NonceID, error)

// Option configures a [Minter].
type Option func(*Minter)

// WithTTL sets the nonce lifetime. A non-positive duration is ignored, so a
// misconfigured value cannot mint a nonce that is already expired.
func WithTTL(ttl time.Duration) Option {
	return func(minter *Minter) {
		if ttl <= 0 {
			return
		}

		minter.ttl = ttl
	}
}

// WithSecretBytes sets the secret length in bytes. Values below
// [defaultSecretBytes] are ignored: the entropy floor is not negotiable.
func WithSecretBytes(size int) Option {
	return func(minter *Minter) {
		if size < defaultSecretBytes {
			return
		}

		minter.secretBytes = size
	}
}

// WithClock replaces the time source. A nil clock is ignored.
func WithClock(clock Clock) Option {
	return func(minter *Minter) {
		if clock == nil {
			return
		}

		minter.now = clock
	}
}

// WithIDGenerator replaces the nonce-ID source. A nil generator is ignored.
func WithIDGenerator(generator IDGenerator) Option {
	return func(minter *Minter) {
		if generator == nil {
			return
		}

		minter.newID = generator
	}
}

// WithBroker sets the broker endpoint written into every bootstrap payload: the
// URL the guest contacts and the TLS certificate fingerprint it pins.
func WithBroker(url BrokerURL, fingerprint BrokerFingerprint) Option {
	return func(minter *Minter) {
		minter.brokerURL = url
		minter.brokerFingerprint = fingerprint
	}
}

// Minter runs the nonce lifecycle over the [Store] and [BootstrapWriter] ports.
// It holds no global state; every instance carries its own policy.
type Minter struct {
	// store is the nonce persistence port. It is required and never nil after
	// [NewMinter] returns.
	store Store
	// writer is the bootstrap configuration port. It is required and never nil
	// after [NewMinter] returns.
	writer BootstrapWriter
	// now is the injected time source.
	now Clock
	// newID is the injected nonce-ID source.
	newID IDGenerator
	// brokerURL is the endpoint written into every payload.
	brokerURL BrokerURL
	// brokerFingerprint is the certificate fingerprint written into every
	// payload.
	brokerFingerprint BrokerFingerprint
	// ttl is the nonce lifetime applied at mint time.
	ttl time.Duration
	// secretBytes is the secret length in bytes drawn from [crypto/rand].
	secretBytes int
}

// NewMinter returns a [Minter] that persists through store and writes bootstrap
// payloads through writer. The defaults are a [defaultTTL] lifetime, a
// [defaultSecretBytes]-byte secret, [time.Now], and a random hexadecimal
// nonce ID.
func NewMinter(store Store, writer BootstrapWriter, opts ...Option) *Minter {
	if store == nil {
		panic("nonce: NewMinter requires a non-nil Store")
	}

	if writer == nil {
		panic("nonce: NewMinter requires a non-nil BootstrapWriter")
	}

	minter := &Minter{
		store:             store,
		writer:            writer,
		now:               time.Now,
		newID:             generateID,
		brokerURL:         "",
		brokerFingerprint: "",
		ttl:               defaultTTL,
		secretBytes:       defaultSecretBytes,
	}
	for _, opt := range opts {
		if opt == nil {
			continue
		}

		opt(minter)
	}

	return minter
}

// Mint issues a nonce bound to one instance UUID plus one generation and writes
// the bootstrap payload onto the named instance.
//
// The call order is load-bearing. The hashed record is stored first and the
// payload written second, so a crash between the two leaves an unusable record
// and no readable secret; the reverse order could leave a readable secret that
// no store can consume or revoke. When the write fails, the record is deleted
// again and the returned error wraps [ErrWriterUnavailable].
//
// name is the write address only, because the bootstrap-writer credential is
// denied reads and cannot resolve a UUID itself. The caller MUST have
// re-resolved name from uuid immediately before this call: Incus instance names
// are reusable, so a stale name can address a different instance.
func (m *Minter) Mint(
	ctx context.Context,
	project attestor.ProjectName,
	name attestor.InstanceName,
	uuid attestor.InstanceUUID,
	generation attestor.GenerationUUID,
) (Issued, error) {
	if name == "" || uuid == "" || generation == "" {
		return Issued{}, errors.New("nonce: mint requires an instance name, uuid, and generation")
	}

	id, err := m.newID()
	if err != nil {
		return Issued{}, fmt.Errorf("nonce: generate nonce id: %w", err)
	}

	secret, err := generateSecret(m.secretBytes)
	if err != nil {
		return Issued{}, fmt.Errorf("nonce: generate nonce secret %s: %w", id, err)
	}

	record := Record{
		ID:         id,
		Hash:       HashSecret(secret),
		Instance:   uuid,
		Generation: generation,
		Project:    project,
		ExpiresAt:  m.now().Add(m.ttl),
		Used:       false,
	}
	if putErr := m.store.Put(ctx, record); putErr != nil {
		return Issued{}, fmt.Errorf("%w: put nonce %s: %w", ErrStoreUnavailable, id, putErr)
	}

	payload, err := json.Marshal(Payload{
		Secret:            secret,
		NonceID:           id,
		BrokerURL:         m.brokerURL,
		BrokerFingerprint: m.brokerFingerprint,
	})
	if err != nil {
		return Issued{}, m.abandon(ctx, id, err)
	}

	if writeErr := m.writer.WriteBootstrap(ctx, project, name, string(payload)); writeErr != nil {
		failure := fmt.Errorf("%w: write bootstrap on %s: %w", ErrWriterUnavailable, name, writeErr)

		return Issued{}, m.abandon(ctx, id, failure)
	}

	return Issued{ID: id, Secret: secret, ExpiresAt: record.ExpiresAt}, nil
}

// Redeem consumes the nonce identified by id and confirms it is bound to the
// live instance the read path resolved independently.
//
// live is authoritative. A caller-claimed UUID is never trusted, which is what
// stops one guest from presenting its own valid nonce while asking for another
// instance's identity: the record's binding must match live, or redemption
// fails with [ErrInstanceMismatch]. A generation that no longer matches means
// the instance was rolled back after minting and yields
// [ErrGenerationChanged].
//
// The consume step commits Used=true before the caller clears the bootstrap key
// with [Minter.Clear]. That order is deliberate: a crash between the two leaves
// a consumed value in the instance configuration, which is harmless, instead of
// a cleared key over a still-reusable credential.
func (m *Minter) Redeem(
	ctx context.Context,
	id NonceID,
	secret Secret,
	live attestor.InstanceRecord,
) (Record, error) {
	if id == "" {
		return Record{}, fmt.Errorf("%w: empty nonce id", ErrNonceNotFound)
	}

	if secret.IsZero() {
		return Record{}, fmt.Errorf("%w: empty secret for nonce %s", ErrSecretMismatch, id)
	}

	record, err := m.store.ConsumeOnce(ctx, id, HashSecret(secret), m.now())
	if err != nil {
		return Record{}, classifyConsume(id, err)
	}

	if record.Instance != live.UUID {
		return Record{}, fmt.Errorf(
			"%w: nonce %s is bound to another instance than live %s",
			ErrInstanceMismatch, id, live.UUID,
		)
	}

	if record.Generation != live.Generation {
		return Record{}, fmt.Errorf(
			"%w: nonce %s was minted for an earlier generation of %s",
			ErrGenerationChanged, id, live.UUID,
		)
	}

	return record, nil
}

// Clear empties the bootstrap configuration key on the named instance. Call it
// after [Minter.Redeem] returns successfully, never before: the consume commit
// is what makes the value in the instance configuration harmless.
//
// As with [Minter.Mint], name must have been re-resolved from the instance UUID
// immediately beforehand.
func (m *Minter) Clear(ctx context.Context, project attestor.ProjectName, name attestor.InstanceName) error {
	if err := m.writer.ClearBootstrap(ctx, project, name); err != nil {
		return fmt.Errorf("%w: clear bootstrap on %s: %w", ErrWriterUnavailable, name, err)
	}

	return nil
}

// abandon removes a record whose bootstrap write never landed, so a nonce that
// no guest can read does not stay redeemable. A failed cleanup is joined onto
// cause instead of replacing it.
func (m *Minter) abandon(ctx context.Context, id NonceID, cause error) error {
	if err := m.store.Delete(ctx, id); err != nil {
		return errors.Join(cause, fmt.Errorf("%w: delete nonce %s: %w", ErrStoreUnavailable, id, err))
	}

	return cause
}

// classifyConsume separates a lifecycle answer from a backend fault. A store
// that already named the lifecycle outcome keeps its sentinel; anything else
// becomes [ErrStoreUnavailable], so a broken backend is never reported as a
// rejected nonce.
func classifyConsume(id NonceID, err error) error {
	switch {
	case errors.Is(err, ErrNonceNotFound),
		errors.Is(err, ErrNonceExpired),
		errors.Is(err, ErrNonceAlreadyUsed),
		errors.Is(err, ErrSecretMismatch):
		return fmt.Errorf("nonce: consume nonce %s: %w", id, err)
	default:
		return fmt.Errorf("%w: consume nonce %s: %w", ErrStoreUnavailable, id, err)
	}
}

// generateSecret draws size bytes from [crypto/rand] and returns them
// hex-encoded, so the secret survives JSON and configuration transport
// unchanged.
func generateSecret(size int) (Secret, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return Secret{}, fmt.Errorf("read %d random bytes: %w", size, err)
	}

	return NewSecret(hex.EncodeToString(buf)), nil
}

// generateID is the default [IDGenerator]. It returns a hex-encoded
// [idBytes]-byte random identifier, which is public data.
func generateID() (NonceID, error) {
	buf := make([]byte, idBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("read %d random bytes: %w", idBytes, err)
	}

	return NonceID(hex.EncodeToString(buf)), nil
}

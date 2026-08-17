package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/anypb"

	"github.com/componere/incusos-spire/internal/attestor"
	"github.com/componere/incusos-spire/internal/broker"
	"github.com/componere/incusos-spire/internal/nonce"
	incusv1alpha1 "github.com/componere/incusos-spire/proto/componere/incus/v1alpha1"
)

const (
	// mintPath is the operator endpoint that provisions one guest.
	mintPath = "/v1alpha1/nonce"
	// redeemPath is the guest endpoint that redeems a bootstrap value.
	redeemPath = "/v1alpha1/redeem"
	// maxRequestBytes caps a request body. Both documents are a handful of
	// short strings, so anything larger is a mistake or an attack.
	maxRequestBytes = 4096
	// contentTypeJSON is the media type of every answer, including failures.
	contentTypeJSON = "application/json"
	// headerAuthorization carries the operator bearer token on the mint path.
	headerAuthorization = "Authorization"
	// headerAuthenticate names the challenge header a refused mint answers with.
	headerAuthenticate = "WWW-Authenticate"
	// bearerScheme is the only authorization scheme the mint path accepts.
	bearerScheme = "Bearer"
	// bearerChallenge is the value of the challenge header on a refused mint. It
	// names the scheme and nothing about why the presentation failed.
	//nolint:gosec // G101 false positive: this is an authentication challenge, not a credential.
	bearerChallenge = `Bearer realm="incus-spiffe-broker"`
)

const (
	// codeInvalidRequest names a request this service could not parse.
	codeInvalidRequest = "invalid_request"
	// codeUnauthorized names a refused presentation of a credential: a nonce
	// on the guest path, the operator bearer token on the mint path. It is the
	// single code for an unknown nonce, a wrong secret, a missing token, and a
	// wrong token alike, so no answer can be used to enumerate anything.
	codeUnauthorized = "unauthorized"
	// codeConflict names a nonce or instance state that cannot be redeemed:
	// expired, already used, bound elsewhere, or rolled back.
	codeConflict = "conflict"
	// codeMethodNotAllowed names a request method other than POST.
	codeMethodNotAllowed = "method_not_allowed"
	// codeInternal names a fault an operator must fix.
	codeInternal = "internal"
	// codeUnavailable names a transient fault a caller may retry.
	codeUnavailable = "unavailable"
	// codeNonceConsumedWithoutSVID names the one outcome that is neither a
	// refused presentation nor a condition worth retrying: the nonce was
	// accepted, atomically consumed, and then no exchange SVID reached the
	// guest. Every failure after [nonce.Minter.Redeem] commits answers with it,
	// whatever the status class, because the status alone cannot carry that
	// distinction: a 503 from a burned nonce and a 503 from a broken store look
	// identical to a guest, and only one of them is worth retrying.
	//
	// The contract it states is exact. The nonce is gone. Presenting it again
	// answers 409 with [codeConflict] and always will, so a guest that sees this
	// code must stop retrying and obtain a fresh nonce from an operator. Nothing
	// beyond the code is in the body; the failure class is in the log.
	codeNonceConsumedWithoutSVID = "nonce_consumed_without_svid"
)

const (
	// operationMint labels the operator path in log records.
	operationMint = "mint"
	// operationRedeem labels the guest path in log records.
	operationRedeem = "redeem"
	// operationReap labels the expired-nonce sweep in log records.
	operationReap = "reap"
)

// The names of the log fields that appear in more than one record. They are
// constants so the shape of a decision record cannot drift between the call
// sites the live run reads together.
const (
	// fieldOperation names which endpoint or task produced the record.
	fieldOperation = "operation"
	// fieldOutcome names the decision: granted or denied.
	fieldOutcome = "outcome"
	// fieldNonceID names the public nonce identifier.
	fieldNonceID = "nonce_id"
	// fieldInstanceUUID names the bound volatile.uuid.
	fieldInstanceUUID = "instance_uuid"
	// fieldInstanceName names the live instance name.
	fieldInstanceName = "instance_name"
	// fieldProject names the Incus project.
	fieldProject = "project"
	// fieldExpiresAt names the instant a nonce stops being redeemable.
	fieldExpiresAt = "expires_at"
	// fieldHTTPStatus names the answered status code.
	fieldHTTPStatus = "http_status"
	// fieldCode names the answered error code.
	fieldCode = "code"
	// fieldReason names the detail that never reaches the caller.
	fieldReason = "reason"
	// fieldPeerAddress names the address the request arrived from.
	fieldPeerAddress = "peer_address"
	// fieldWithdrawal names why a withdrawal did not complete.
	fieldWithdrawal = "withdrawal"
	// fieldFailureClass names which class of failure produced a record. It is
	// the field that separates a burned nonce from a rejected one.
	fieldFailureClass = "failure_class"
	// fieldExchangeID names the SPIFFE ID of an issued exchange SVID.
	fieldExchangeID = "exchange_spiffe_id"
	// fieldExchangeExpiresAt names the instant an exchange SVID stops being
	// usable for node attestation.
	fieldExchangeExpiresAt = "exchange_expires_at"
)

// The exchange-SVID vocabulary: the reference this service submits to the
// Broker API, the PEM types it hands the guest, and the redacted rendering of
// the private key it must never print.
const (
	// referenceTypeURL is the google.protobuf.Any type URL of the workload
	// reference this service submits. It must equal the host agent's
	// brokers[].allowed_reference_types[].type_url and the type URL
	// cmd/incus-attestor attests, exactly; SPIRE answers PermissionDenied for
	// anything else.
	referenceTypeURL = "type.googleapis.com/componere.incus.v1alpha1.IncusInstanceReference"
	// pemTypeCertificate is the PEM block type of an X.509 certificate.
	pemTypeCertificate = "CERTIFICATE"
	// pemTypePrivateKey is the PEM block type of an unencrypted PKCS#8 private
	// key, which is the form SPIRE's x509pop key_path accepts.
	pemTypePrivateKey = "PRIVATE KEY"
	// redactedExchangeKey is the fixed text every formatting path of an
	// [exchangeKeyPEM] renders instead of key material.
	redactedExchangeKey = "exchange-key(redacted)"
)

// The failure classes of a burned redemption: every way a nonce can be spent
// without its guest receiving an exchange SVID. They exist so an operator
// reading the log can tell a burned nonce apart from a rejected one, and can
// tell which side failed: an allowlist or registration fault they must fix, a
// transport fault the guest may retry after a fresh mint, or an instance that
// changed underneath the redemption.
const (
	// classReferenceTypeDenied names a reference type outside the host agent's
	// broker allowlist. Attestation never ran.
	classReferenceTypeDenied = "broker_reference_type_denied"
	// classPermissionDenied names a refusal this service cannot attribute: the
	// allowlist, or the workload attestor's own policy after it attested.
	classPermissionDenied = "broker_permission_denied"
	// classInvalidRequest names a request the Broker endpoint rejected outright,
	// which is a fault in this service or its configuration.
	classInvalidRequest = "broker_invalid_request"
	// classTransport names a transport or TLS failure against the broker socket.
	classTransport = "broker_transport"
	// classTimeout names a Broker call that ran out of time.
	classTimeout = "broker_timeout"
	// classNoSVID names a subscription the endpoint accepted and then ended
	// without delivering an SVID.
	classNoSVID = "broker_no_svid"
	// classMaterialInvalid names an SVID this service could not convert into the
	// PEM triple a guest agent can use.
	classMaterialInvalid = "exchange_material_invalid"
	// classUnknown names a Broker failure with no documented sentinel.
	classUnknown = "broker_unknown"
	// classSelectorDerivation names a selector derivation that failed after the
	// consume committed: the instance changed under the redemption, or the read
	// path behind the deriver refused. The Broker API was never reached, so no
	// exchange credential exists for this nonce anywhere.
	classSelectorDerivation = "selector_derivation"
)

// errExchangeMaterial reports an SVID the Broker API delivered that this service
// could not turn into usable PEM. It is this package's own fault class, distinct
// from every internal/broker sentinel, so a structurally broken delivery is not
// laundered into a transport problem an operator would look for in the wrong
// place.
var errExchangeMaterial = errors.New("exchange SVID material is unusable")

// bindingLookup is the slice of the nonce store this service reads directly: it
// answers "which instance is this nonce bound to" before anything is resolved
// or consumed. It is a lookup, never a redemption path;
// [nonce.Minter.Redeem] performs the atomic consume.
type bindingLookup interface {
	// Get returns the stored record for id without consuming it.
	Get(ctx context.Context, id nonce.NonceID) (nonce.Record, error)
}

// nonceMinter is the port into the nonce lifecycle core. The service owns no
// lifecycle rules of its own; it translates HTTP into a core call and the core
// answer into an HTTP answer.
type nonceMinter interface {
	// Mint issues a nonce bound to one instance UUID plus one generation and
	// writes the bootstrap payload onto the named instance.
	Mint(
		ctx context.Context,
		project attestor.ProjectName,
		name attestor.InstanceName,
		uuid attestor.InstanceUUID,
		generation attestor.GenerationUUID,
		opts ...nonce.MintOption,
	) (nonce.Issued, error)
	// Redeem consumes the nonce and confirms it is bound to live, the record
	// the read path resolved independently.
	Redeem(
		ctx context.Context,
		id nonce.NonceID,
		secret nonce.Secret,
		live attestor.InstanceRecord,
	) (nonce.Record, error)
	// Clear empties the bootstrap configuration key. It runs after a
	// redemption commits, never before.
	Clear(ctx context.Context, project attestor.ProjectName, name attestor.InstanceName) error
	// Revoke withdraws a nonce nobody redeemed: it clears the bootstrap key and
	// deletes the record. The service calls it to compensate a mint whose
	// operator never learned the nonce ID.
	Revoke(
		ctx context.Context,
		id nonce.NonceID,
		project attestor.ProjectName,
		name attestor.InstanceName,
	) error
}

// selectorDeriver is the port into the pure selector core. The service does not
// derive selectors and does not know the trust rules behind them.
type selectorDeriver interface {
	// Derive returns the frozen selector set for the referenced instance.
	Derive(ctx context.Context, ref attestor.Reference) ([]attestor.Selector, error)
}

// exchangeIssuer is the port into the SPIRE Broker API. It is the one port whose
// answer is credential material rather than a description of one, and
// github.com/componere/incusos-spire/internal/broker is the only package that
// implements it: the experimental Broker proto stays behind that adapter, and
// this service links only the vendor reference message it submits.
//
// The port is narrow on purpose. This service cannot ask the Broker API for an
// arbitrary identity: it submits one opaque workload reference and takes
// whatever the host agent's attestor plugin and the server's registration
// entries decide that reference is worth.
type exchangeIssuer interface {
	// FetchX509SVID returns the X.509-SVID SPIRE issues for reference, together
	// with the trust bundle of its trust domain.
	FetchX509SVID(ctx context.Context, reference *anypb.Any) (broker.X509SVID, error)
}

// expiredLister is the slice of the nonce store the reaper reads: the records
// whose TTL elapsed with nobody redeeming them, which are exactly the records
// whose bootstrap key may still hold a live secret.
type expiredLister interface {
	// ListExpired returns the expired, unconsumed records at now.
	ListExpired(ctx context.Context, now time.Time) ([]nonce.Record, error)
}

// nonceWithdrawer is the port the reaper drives. It is narrower than
// [nonceMinter] on purpose: a sweep may only withdraw, never mint or redeem.
type nonceWithdrawer interface {
	// Revoke clears the bootstrap key of an unredeemed nonce and deletes its
	// record. It refuses a record that was consumed in the meantime.
	Revoke(
		ctx context.Context,
		id nonce.NonceID,
		project attestor.ProjectName,
		name attestor.InstanceName,
	) error
	// Discard deletes the record of an unredeemed nonce without touching any
	// instance configuration. It is the withdrawal for a nonce whose instance no
	// longer exists.
	Discard(ctx context.Context, id nonce.NonceID) error
}

// mintRequest is the operator request body. project is optional and defaults to
// the read adapter's configured project.
type mintRequest struct {
	// InstanceUUID is the volatile.uuid of the instance to provision. It is the
	// only identity anchor a caller may supply, and it is resolved through the
	// read path rather than trusted.
	InstanceUUID string `json:"instance_uuid"`
	// Project scopes the lookup. Empty means the configured default project.
	Project string `json:"project"`
	// TTLSeconds optionally shortens the lifetime of this one nonce. Absent
	// means the service's configured TTL; a value that is not positive or that
	// exceeds the configured maximum is refused rather than clamped, because an
	// operator who asked for a five-second window and silently received ten
	// minutes has been told something untrue about a bearer credential.
	TTLSeconds *int64 `json:"ttl_seconds"`
}

// mintResponse is the operator answer.
//
// It has no secret field, by design. The nonce secret reaches exactly one
// destination, the guest-readable instance configuration key, so possession of
// it is evidence of a read from inside the bound instance. Returning it here
// would create a second copy of a bearer credential in every place an operator
// response can be recorded.
type mintResponse struct {
	// NonceID is the public identifier the guest presents at redemption.
	NonceID nonce.NonceID `json:"nonce_id"`
	// ExpiresAt is the instant the nonce stops being redeemable.
	ExpiresAt time.Time `json:"expires_at"`
	// InstanceUUID is the resolved volatile.uuid the nonce is bound to.
	InstanceUUID attestor.InstanceUUID `json:"instance_uuid"`
	// InstanceName is the name freshly resolved from the UUID and used as the
	// write address. It is reported so an operator can confirm which instance
	// received the key.
	InstanceName attestor.InstanceName `json:"instance_name"`
	// Generation is the bound volatile.uuid.generation. A snapshot restore
	// replaces it and invalidates the nonce.
	Generation attestor.GenerationUUID `json:"generation"`
	// Project is the resolved project of the bound instance.
	Project attestor.ProjectName `json:"project"`
}

// redeemRequest is the guest request body: the bootstrap payload as the guest
// read it out of user.spiffe-bootstrap.
//
// All four payload fields are accepted so a guest may forward the document it
// read verbatim, and the two that address the broker are ignored: a caller
// cannot tell this service where to find itself. Any other field is refused
// with 400, so a stale client or a typo is reported instead of silently
// dropped. That includes instance_uuid: the binding is resolved server-side
// from the nonce record, and a caller-claimed identity is not merely ignored,
// it is not accepted at all.
type redeemRequest struct {
	// NonceID is the public nonce identifier.
	NonceID string `json:"nonce_id"`
	// Nonce is the presented secret. It is converted to a [nonce.Secret]
	// immediately after decoding and this field is zeroed, so the raw material
	// has the shortest possible life. [redeemRequest.LogValue] and
	// [redeemRequest.String] redact it in the meantime.
	Nonce string `json:"nonce"`
	// BrokerURL is the endpoint the guest was told to contact. It is accepted
	// because it is part of the payload document and ignored because the
	// request already arrived here.
	BrokerURL string `json:"broker_url"`
	// BrokerFingerprint is the certificate the guest was told to pin. It is
	// accepted for the same reason and ignored because the guest has already
	// completed the handshake this value governs.
	BrokerFingerprint string `json:"broker_fingerprint"`
}

// String redacts the request. It satisfies [fmt.Stringer] so that %v and %s on
// a decoded request cannot print the presented secret.
func (r redeemRequest) String() string {
	return "redeemRequest(nonce_id=" + r.NonceID + ", nonce=" + nonce.RedactedSecret + ")"
}

// LogValue redacts the request for [log/slog]. It satisfies
// [log/slog.LogValuer] so that structured logging cannot record the presented
// secret.
func (r redeemRequest) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("nonce_id", r.NonceID),
		slog.String("nonce", nonce.RedactedSecret),
	)
}

// exchangeKeyPEM is the PKCS#8 PEM private key of an exchange SVID.
//
// It is a distinct type because it is the most sensitive value this process ever
// holds, and it is modelled on [nonce.Secret] for the same reason:
// [exchangeKeyPEM.String], [exchangeKeyPEM.GoString], [exchangeKeyPEM.Format],
// and [exchangeKeyPEM.LogValue] all render [redactedExchangeKey], so the key
// cannot reach a log line, an error string, or any [fmt] verb.
// [exchangeKeyPEM.MarshalJSON] is the single deliberate reveal, and its only
// caller is the encoder that writes the redemption answer to the guest that just
// proved it owns this identity.
//
// The limitation of that guard is exact and must not be forgotten: JSON
// marshalling is not redaction, it is the reveal. Every other rendering path is
// safe by construction, but any sink that marshals instead of formatting —
// a JSON-marshalling logger, an audit writer, a metrics label built with
// [encoding/json], an error type that marshals its cause — receives the key
// itself. The rule that follows: this type, and any struct containing it, must
// never be handed to a sink that marshals. Today the only marshaller in the
// process is the encoder in [Service.writeJSON] answering the guest, and the
// [log/slog] path is safe because [redeemResponse.LogValue] resolves before any
// handler can marshal. Every new sink has to be checked against that rule; a
// [log/slog.Handler] swapped for one that marshals attribute values would leak
// the key with no other change to this package.
//
// Neither the material nor its length is ever reported. A length is a fact about
// a private key, and a log line that carries one for a specific nonce ID has
// described that key.
type exchangeKeyPEM struct {
	// pem is the PEM-encoded PKCS#8 key. Nothing formats, measures, or copies it
	// except [exchangeKeyPEM.MarshalJSON].
	pem []byte
}

// newExchangeKeyPEM wraps PEM-encoded PKCS#8 key material.
func newExchangeKeyPEM(encoded []byte) exchangeKeyPEM {
	return exchangeKeyPEM{pem: encoded}
}

// MarshalJSON encodes the key as a JSON string. It is the one deliberate reveal
// of this type and exists so the guest receives usable material; see the type
// documentation for why nothing else may.
func (k exchangeKeyPEM) MarshalJSON() ([]byte, error) {
	encoded, err := json.Marshal(string(k.pem))
	if err != nil {
		return nil, fmt.Errorf("marshal exchange private key: %w", err)
	}

	return encoded, nil
}

// String returns [redactedExchangeKey]. It satisfies [fmt.Stringer] so that %v
// and %s can never print key material.
func (k exchangeKeyPEM) String() string {
	return redactedExchangeKey
}

// Format writes [redactedExchangeKey] for every verb. It satisfies
// [fmt.Formatter], which [fmt] consults ahead of [fmt.Stringer] and for verbs
// such as %d and %q that a Stringer does not cover, so no verb can reach the key
// material.
func (k exchangeKeyPEM) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, redactedExchangeKey)
}

// GoString returns [redactedExchangeKey]. It satisfies [fmt.GoStringer] so that
// %#v can never print key material.
func (k exchangeKeyPEM) GoString() string {
	return redactedExchangeKey
}

// LogValue returns [redactedExchangeKey] as a [log/slog] value. It satisfies
// [log/slog.LogValuer] so that structured logging can never record key material.
func (k exchangeKeyPEM) LogValue() slog.Value {
	return slog.StringValue(redactedExchangeKey)
}

// exchangeMaterial is one exchange SVID in the encoding a SPIRE agent reads: PEM
// files for x509pop's certificate_path, private_key_path, and the trust bundle.
type exchangeMaterial struct {
	// ID is the SPIFFE ID SPIRE issued, expected to be
	// spiffe://<trust domain>/spire-exchange/incus/<instance uuid>.
	ID broker.SPIFFEID
	// ChainPEM is the certificate chain, leaf first.
	ChainPEM string
	// BundlePEM is the X.509 bundle of the trust domain.
	BundlePEM string
	// Key is the PKCS#8 private key for ChainPEM.
	Key exchangeKeyPEM
	// ExpiresAt is the leaf's NotAfter: the instant the guest can no longer
	// attest with this material.
	ExpiresAt time.Time
}

// redeemResponse is the guest answer on a successful redemption.
//
// This body carries a private key. It is the single most sensitive response in
// the system: whoever holds exchange_key_pem together with
// exchange_cert_chain_pem can complete x509pop node attestation as
// spiffe://<trust domain>/spire/agent/x509pop/incus/<instance uuid> until
// exchange_expires_at. It is therefore returned exactly once, to the caller that
// just proved possession of the bound instance's one-time nonce, over TLS, and
// it is never logged, never stored by this service, and never re-issuable for
// the same nonce.
//
// The guest must hold this material in memory-backed storage only: a tmpfs
// directory, written, used once to attest, and gone at the next boot. Writing it
// to a persistent guest disk would turn a short-lived credential into a durable
// one that survives every control this design has. The spike records that
// delivery-and-holding question as a known-unsolved design point (P9 step 2)
// rather than claiming to have closed it: the guest is given the key, so the
// guest's own storage decision is load-bearing and unenforceable from here.
//
// This type must never be handed to a sink that marshals it. Its
// [redeemResponse.String] and [redeemResponse.LogValue] are the whole reason a
// careless log line does not leak the key, and they only cover formatting and
// [log/slog]: marshalling this struct is exactly what answering the guest does,
// so [encoding/json] on it produces the key in the clear by design. Both methods
// are load-bearing security controls rather than conveniences, and
// TestRedeemResponseRedactionCannotRegress exists so removing either one fails
// the build's tests instead of silently opening that path.
//
// The P8 fields are kept. The selector list is what the live run reads to
// confirm which identity was proved, and it is secret-free.
type redeemResponse struct {
	// NonceID echoes the consumed nonce identifier.
	NonceID nonce.NonceID `json:"nonce_id"`
	// InstanceUUID is the bound volatile.uuid, resolved server-side.
	InstanceUUID attestor.InstanceUUID `json:"instance_uuid"`
	// InstanceName is the live name of the bound instance.
	InstanceName attestor.InstanceName `json:"instance_name"`
	// Generation is the live volatile.uuid.generation that matched the binding.
	Generation attestor.GenerationUUID `json:"generation"`
	// Project is the project of the bound instance.
	Project attestor.ProjectName `json:"project"`
	// Selectors are the frozen incus: selectors derived for the bound instance.
	Selectors []attestor.Selector `json:"selectors"`
	// ExchangeSPIFFEID is the SPIFFE ID of the exchange SVID.
	ExchangeSPIFFEID broker.SPIFFEID `json:"exchange_spiffe_id"`
	// ExchangeCertChainPEM is the exchange certificate chain, leaf first, for
	// x509pop's certificate_path.
	ExchangeCertChainPEM string `json:"exchange_cert_chain_pem"`
	// ExchangeKeyPEM is the PKCS#8 private key for x509pop's private_key_path.
	// It is the reason this type's documentation exists.
	ExchangeKeyPEM exchangeKeyPEM `json:"exchange_key_pem"`
	// ExchangeBundlePEM is the trust bundle of the trust domain, which the guest
	// agent needs to verify the server it is about to attest to.
	ExchangeBundlePEM string `json:"exchange_bundle_pem"`
	// ExchangeExpiresAt is the leaf's NotAfter. After it, this material attests
	// nothing and the guest needs a fresh nonce.
	ExchangeExpiresAt time.Time `json:"exchange_expires_at"`
}

// String redacts the answer. It satisfies [fmt.Stringer] so that %v and %s on a
// composed answer cannot print the key it carries. [exchangeKeyPEM] already
// refuses every verb on its own; this refuses the enclosing document too, because
// a struct is only ever one careless %+v away from its fields.
//
// It is a required control, not a nicety. See the type documentation: nothing
// here defends against a sink that marshals.
func (r redeemResponse) String() string {
	return "redeemResponse(nonce_id=" + string(r.NonceID) +
		", exchange_spiffe_id=" + string(r.ExchangeSPIFFEID) +
		", exchange_key_pem=" + redactedExchangeKey + ")"
}

// LogValue redacts the answer for [log/slog]. It is the guard that matters most:
// [log/slog] resolves a [log/slog.LogValuer] only at the top of an attribute, so
// a handler handed this whole struct would otherwise fall back to marshalling it,
// and marshalling is the one path that deliberately reveals the key. Removing this
// method would therefore turn any JSON handler into a key leak, which is why
// TestRedeemResponseRedactionCannotRegress asserts it exists.
func (r redeemResponse) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String(fieldNonceID, string(r.NonceID)),
		slog.String(fieldInstanceUUID, string(r.InstanceUUID)),
		slog.String(fieldExchangeID, string(r.ExchangeSPIFFEID)),
		slog.String("exchange_key_pem", redactedExchangeKey),
	)
}

// errorResponse is the uniform failure body. It names the status class and never
// the cause, so no answer distinguishes an unknown nonce from a wrong secret.
//
// [codeNonceConsumedWithoutSVID] is the one code that is not a status class, and
// it is not a cause either: it names a state of the nonce, which the guest cannot
// otherwise learn and must act on. It appears only after a consume committed, so
// it reveals nothing to a caller that did not already spend a valid nonce.
type errorResponse struct {
	// Error is one of the code constants of this package.
	Error string `json:"error"`
}

// ServiceConfig carries the collaborators of a [Service]. Every field is
// required; composition happens in main.
type ServiceConfig struct {
	// Reader is the read-only Incus identity path. It resolves a UUID to the
	// live instance record and is the only source of an instance name.
	Reader attestor.InstanceReader
	// Bindings answers which instance a nonce is bound to.
	Bindings bindingLookup
	// Minter runs the nonce lifecycle over the store and the bootstrap writer.
	Minter nonceMinter
	// Deriver produces the frozen selector set for a redeemed instance.
	Deriver selectorDeriver
	// Exchange obtains the exchange SVID a redeemed guest receives. It is
	// required: a redemption that cannot issue one has nothing to answer with.
	Exchange exchangeIssuer
	// Logger receives every mint and every redemption decision.
	Logger *slog.Logger
	// MintTokenDigest is the SHA-256 of the operator bearer token that
	// authorizes the mint path. The digest is held instead of the token so the
	// running service never carries the credential itself, and the comparison
	// is over two fixed-length values.
	MintTokenDigest [sha256.Size]byte
	// MaxNonceTTL is the longest lifetime a mint request may ask for. A request
	// above it is refused.
	MaxNonceTTL time.Duration
	// CompensationTimeout bounds the detached withdrawal of a mint whose caller
	// went away before it could learn the nonce ID.
	CompensationTimeout time.Duration
}

// Service serves the two bootstrap endpoints. It holds no mutable state: the
// nonce state lives in the store behind the minter.
type Service struct {
	// reader resolves a UUID to the live instance record.
	reader attestor.InstanceReader
	// bindings answers which instance a nonce is bound to.
	bindings bindingLookup
	// minter runs the nonce lifecycle.
	minter nonceMinter
	// deriver produces the frozen selector set.
	deriver selectorDeriver
	// exchange obtains the exchange SVID a redeemed guest receives.
	exchange exchangeIssuer
	// logger receives every decision this service makes.
	logger *slog.Logger
	// mintTokenDigest is the SHA-256 of the accepted operator bearer token.
	mintTokenDigest [sha256.Size]byte
	// maxNonceTTL is the longest lifetime a mint request may ask for.
	maxNonceTTL time.Duration
	// compensationTimeout bounds a detached mint withdrawal.
	compensationTimeout time.Duration
}

// NewService validates cfg and returns a concrete [Service].
//
// A missing collaborator is a composition error and is reported here, before
// the listener opens, rather than as a nil dereference on the first request.
func NewService(cfg ServiceConfig) (*Service, error) {
	switch {
	case cfg.Reader == nil:
		return nil, errors.New("broker: service requires an instance reader")
	case cfg.Bindings == nil:
		return nil, errors.New("broker: service requires a nonce binding lookup")
	case cfg.Minter == nil:
		return nil, errors.New("broker: service requires a nonce minter")
	case cfg.Deriver == nil:
		return nil, errors.New("broker: service requires a selector deriver")
	case cfg.Exchange == nil:
		return nil, errors.New("broker: service requires an exchange SVID issuer")
	case cfg.Logger == nil:
		return nil, errors.New("broker: service requires a logger")
	case cfg.MintTokenDigest == [sha256.Size]byte{}:
		return nil, errors.New("broker: service requires an operator mint token digest")
	case cfg.MaxNonceTTL <= 0:
		return nil, errors.New("broker: service requires a positive maximum nonce TTL")
	case cfg.CompensationTimeout <= 0:
		return nil, errors.New("broker: service requires a positive compensation timeout")
	}

	return &Service{
		reader:              cfg.Reader,
		bindings:            cfg.Bindings,
		minter:              cfg.Minter,
		deriver:             cfg.Deriver,
		exchange:            cfg.Exchange,
		logger:              cfg.Logger,
		mintTokenDigest:     cfg.MintTokenDigest,
		maxNonceTTL:         cfg.MaxNonceTTL,
		compensationTimeout: cfg.CompensationTimeout,
	}, nil
}

// Handler returns the routed HTTP surface: [mintPath] and [redeemPath], both
// POST only.
//
// The two routes are registered without a method pattern on purpose. The
// mux would answer a wrong method with its own plain-text 405, and every
// failure this service produces must carry the uniform JSON body.
func (s *Service) Handler() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc(mintPath, s.handleMint)
	mux.HandleFunc(redeemPath, s.handleRedeem)

	return mux
}

// handleMint provisions one guest: it authenticates the operator, resolves the
// requested UUID through the read path, and mints a nonce against the freshly
// resolved instance name.
//
// The authorization check comes before every other decision, and in particular
// before the read path is touched. Minting writes a bearer credential into a
// guest's configuration and spends the two privileged Incus credentials to do
// it, so an unauthenticated caller must not be able to reach either one.
//
// The read is not optional and not cacheable. The bootstrap-writer credential
// is denied every read (P5), so it cannot resolve a UUID itself, and an Incus
// instance name is reusable after a delete and recreate (P6), so a name that
// was correct a minute ago can address a different instance now.
func (s *Service) handleMint(w http.ResponseWriter, r *http.Request) {
	if !s.requirePost(w, r, operationMint) || !s.authorizeMint(w, r) {
		return
	}

	var request mintRequest
	if err := decodeRequest(w, r, &request); err != nil {
		s.refuse(r, w, operationMint, "", "", http.StatusBadRequest, codeInvalidRequest, err.Error())

		return
	}

	instanceUUID := attestor.InstanceUUID(strings.TrimSpace(request.InstanceUUID))
	if instanceUUID == "" {
		s.refuse(r, w, operationMint, "", "",
			http.StatusBadRequest, codeInvalidRequest, "instance_uuid is required")

		return
	}

	ttl, err := s.requestedTTL(request)
	if err != nil {
		s.refuse(r, w, operationMint, "", instanceUUID,
			http.StatusBadRequest, codeInvalidRequest, err.Error())

		return
	}

	ctx := r.Context()
	requested := attestor.ProjectName(strings.TrimSpace(request.Project))

	live, err := s.reader.ReadInstanceByUUID(ctx, instanceUUID, requested)
	if err != nil {
		s.deny(r, w, operationMint, "", instanceUUID, err)

		return
	}

	issued, err := s.minter.Mint(ctx, live.Project, live.Name, live.UUID, live.Generation,
		nonce.WithMintTTL(ttl))
	if err != nil {
		s.deny(r, w, operationMint, "", live.UUID, err)

		return
	}

	s.logger.InfoContext(ctx, "bootstrap nonce minted",
		fieldOperation, operationMint,
		fieldNonceID, issued.ID,
		fieldInstanceUUID, live.UUID,
		fieldInstanceName, live.Name,
		"generation", live.Generation,
		fieldProject, live.Project,
		fieldExpiresAt, issued.ExpiresAt,
	)

	s.acknowledgeMint(ctx, w, issued, live)
}

// acknowledgeMint hands the minted nonce ID to the operator, and withdraws the
// nonce again if it cannot.
//
// The bootstrap key is already written at this point, so a caller that never
// receives the answer would leave a live bearer credential in a guest's
// configuration that no operator knows about and no guest was told to expect.
// A cancelled request context and an undeliverable body are the two ways that
// happens, and both are compensated rather than logged and forgotten.
func (s *Service) acknowledgeMint(
	ctx context.Context,
	w http.ResponseWriter,
	issued nonce.Issued,
	live attestor.InstanceRecord,
) {
	if err := ctx.Err(); err != nil {
		s.withdrawMint(ctx, issued.ID, live, err)

		return
	}

	if err := s.writeJSON(ctx, w, http.StatusCreated, mintResponse{
		NonceID:      issued.ID,
		ExpiresAt:    issued.ExpiresAt,
		InstanceUUID: live.UUID,
		InstanceName: live.Name,
		Generation:   live.Generation,
		Project:      live.Project,
	}); err != nil {
		s.withdrawMint(ctx, issued.ID, live, err)
	}
}

// withdrawMint clears the bootstrap key and deletes the record of a nonce whose
// operator never learned its ID.
//
// The withdrawal runs on a context detached from the caller's, because the
// caller is the thing that failed: reusing a cancelled context would make the
// compensation fail exactly when it is needed. If the guest redeemed in the
// meantime the withdrawal is refused by the core and recorded, because the
// redemption path owns the clear for a consumed nonce.
func (s *Service) withdrawMint(
	ctx context.Context,
	id nonce.NonceID,
	live attestor.InstanceRecord,
	cause error,
) {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.compensationTimeout)
	defer cancel()

	record := []any{
		fieldOperation, operationMint,
		fieldNonceID, id,
		fieldInstanceUUID, live.UUID,
		fieldInstanceName, live.Name,
		fieldProject, live.Project,
		fieldReason, cause.Error(),
	}

	err := s.minter.Revoke(cleanup, id, live.Project, live.Name)

	switch {
	case err == nil:
		s.logger.WarnContext(cleanup, "unacknowledged mint withdrawn", record...)
	case errors.Is(err, nonce.ErrNonceAlreadyUsed):
		s.logger.WarnContext(cleanup, "unacknowledged mint was redeemed before it could be withdrawn",
			append(record, fieldWithdrawal, err.Error())...)
	default:
		s.logger.ErrorContext(cleanup, "unacknowledged mint not withdrawn",
			append(record, fieldWithdrawal, err.Error())...)
	}
}

// requestedTTL resolves the lifetime one mint request asks for. A zero result
// means "the service's configured TTL", which is what [nonce.WithMintTTL]
// applies for a non-positive duration.
//
// A request above the configured maximum is refused instead of clamped. The
// answer carries no detail, but the log does, and an operator who asked for a
// window this service will not grant deserves to be told rather than quietly
// given a longer one.
func (s *Service) requestedTTL(request mintRequest) (time.Duration, error) {
	if request.TTLSeconds == nil {
		return 0, nil
	}

	seconds := *request.TTLSeconds
	if seconds <= 0 {
		return 0, fmt.Errorf("ttl_seconds must be positive, got %d", seconds)
	}

	ttl := time.Duration(seconds) * time.Second
	if ttl > s.maxNonceTTL || ttl <= 0 {
		return 0, fmt.Errorf("ttl_seconds must not exceed %d", int64(s.maxNonceTTL/time.Second))
	}

	return ttl, nil
}

// handleRedeem consumes a nonce presented by a guest.
//
// The caller supplies a nonce ID and a secret and nothing else that matters.
// The bound UUID comes from the nonce record, the live instance record comes
// from the read path, and only then is the nonce consumed. A caller-claimed
// instance identity is refused outright, which is what stops one guest from
// presenting its own valid nonce while asking for another instance's identity.
//
// This endpoint carries no operator authentication, unlike [mintPath]. The
// nonce is the guest's credential: a guest has no other secret to present, and
// requiring one would mean provisioning a second credential to protect the
// first. See the package documentation for the full asymmetry argument.
//
// A successful consume is the point of no return. The clear, the selector
// derivation, and the exchange-SVID fetch all run against a nonce that is already
// spent, so a failure among them is reported as this service's fault, never as a
// refused presentation, and always with [codeNonceConsumedWithoutSVID]. See
// [Service.grantExchange].
func (s *Service) handleRedeem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !s.requirePost(w, r, operationRedeem) {
		return
	}

	var request redeemRequest
	if err := decodeRequest(w, r, &request); err != nil {
		s.refuse(r, w, operationRedeem, "", "", http.StatusBadRequest, codeInvalidRequest, err.Error())

		return
	}

	id := nonce.NonceID(strings.TrimSpace(request.NonceID))
	secret := nonce.NewSecret(request.Nonce)
	request.Nonce = ""

	if secret.IsZero() {
		s.deny(r, w, operationRedeem, id, "",
			fmt.Errorf("%w: empty secret presentation", nonce.ErrSecretMismatch))

		return
	}

	record, err := s.bindings.Get(ctx, id)
	if err != nil {
		s.deny(r, w, operationRedeem, id, "", classifyLookup(id, err))

		return
	}

	live, err := s.reader.ReadInstanceByUUID(ctx, record.Instance, record.Project)
	if err != nil {
		s.deny(r, w, operationRedeem, id, record.Instance, err)

		return
	}

	consumed, err := s.minter.Redeem(ctx, id, secret, live)
	if err != nil {
		s.deny(r, w, operationRedeem, id, record.Instance, err)

		return
	}

	// The clear runs before the exchange fetch, not after. The consume has
	// committed, so the value in user.spiffe-bootstrap no longer redeems, but it
	// is still a readable string in that instance's configuration and the reaper
	// deliberately leaves consumed records alone forever. Clearing first bounds
	// how long that dead value lingers to this request; clearing afterwards would
	// mean every Broker failure — a timeout, an unreachable socket, a
	// misconfigured registration entry — left it readable indefinitely. The clear
	// never fails the redemption either way, so ordering it first cannot cost the
	// guest its SVID.
	s.clearBootstrap(ctx, consumed.ID, live)

	s.grantExchange(w, r, consumed, live)
}

// grantExchange completes a committed redemption: it derives the selector set,
// obtains the exchange SVID for the bound instance, and answers the guest.
//
// The nonce is already spent when this runs, which changes what every failure in
// here means. It is not "your nonce was rejected", it is "your nonce is gone and
// you got nothing for it", so both failures answer with
// [codeNonceConsumedWithoutSVID] rather than the code their status class would
// otherwise carry, and both are logged with a failure class an operator can act
// on. See [Service.burn]. The statuses are unchanged: the exchange fetch keeps
// the 500/503 split of [exchangeFailure] and a derivation failure keeps the
// status the mapping P8 fixed for it, which is the status the live run reads.
//
// The selectors are derived before the SVID is requested. A derivation failure
// then costs nothing beyond the nonce, whereas the reverse order would leave a
// live exchange credential issued for an instance and delivered to nobody.
func (s *Service) grantExchange(
	w http.ResponseWriter,
	r *http.Request,
	consumed nonce.Record,
	live attestor.InstanceRecord,
) {
	ctx := r.Context()

	selectors, err := s.deriver.Derive(ctx, attestor.Reference{
		InstanceUUID: consumed.Instance,
		Project:      consumed.Project,
		Generation:   consumed.Generation,
		Server:       "",
	})
	if err != nil {
		// A derivation failure after the consume is a burned nonce too, not a
		// refused presentation: routing it through deny would answer 409 with
		// the same body a replayed nonce gets, and a guest cannot act on the
		// difference between "already used" and "used just now, by you, for
		// nothing".
		status, _ := failureStatus(err)
		s.burn(r, w, consumed, status, classSelectorDerivation, err)

		return
	}

	exchange, err := s.fetchExchange(ctx, consumed)
	if err != nil {
		status, class := exchangeFailure(err)
		s.burn(r, w, consumed, status, class, err)

		return
	}

	s.logger.InfoContext(ctx, "bootstrap nonce redeemed",
		fieldOperation, operationRedeem,
		fieldOutcome, "granted",
		fieldNonceID, consumed.ID,
		fieldInstanceUUID, consumed.Instance,
		fieldInstanceName, live.Name,
		"generation", consumed.Generation,
		fieldProject, consumed.Project,
		fieldExchangeID, string(exchange.ID),
		fieldExchangeExpiresAt, exchange.ExpiresAt,
		fieldHTTPStatus, http.StatusOK,
	)

	_ = s.writeJSON(ctx, w, http.StatusOK, redeemResponse{
		NonceID:              consumed.ID,
		InstanceUUID:         consumed.Instance,
		InstanceName:         live.Name,
		Generation:           consumed.Generation,
		Project:              consumed.Project,
		Selectors:            selectors,
		ExchangeSPIFFEID:     exchange.ID,
		ExchangeCertChainPEM: exchange.ChainPEM,
		ExchangeKeyPEM:       exchange.Key,
		ExchangeBundlePEM:    exchange.BundlePEM,
		ExchangeExpiresAt:    exchange.ExpiresAt,
	})
}

// fetchExchange obtains the exchange SVID for the instance a consumed nonce was
// bound to, in the PEM encoding a guest agent can use.
//
// The reference is a claim, and that is the whole point of routing it through the
// Broker API rather than signing anything here. This service asserts an instance
// UUID; the host agent's attestor plugin reads that instance back out of
// authoritative Incus state and returns incus:uuid:<uuid> only if it agrees, and
// the SPIRE server matches that selector against the registration entry for
// spiffe://<trust domain>/spire-exchange/incus/<uuid>. The exchange SVID
// therefore exists only because a physically attested host agent independently
// confirmed the instance, which is what makes it worth trusting at all.
//
// The generation is deliberately not claimed. The redemption just verified it
// against live state, and the host plugin derives every selector from live state
// regardless, so asserting it again would only add a way for this service to
// disagree with the authority it is deferring to.
func (s *Service) fetchExchange(ctx context.Context, consumed nonce.Record) (exchangeMaterial, error) {
	reference, err := anypb.New(&incusv1alpha1.IncusInstanceReference{
		InstanceUuid:   string(consumed.Instance),
		Project:        string(consumed.Project),
		GenerationUuid: "",
		Server:         "",
	})
	if err != nil {
		return exchangeMaterial{}, fmt.Errorf("marshal instance reference: %w", err)
	}

	svid, err := s.exchange.FetchX509SVID(ctx, reference)
	if err != nil {
		return exchangeMaterial{}, err
	}

	return exchangePEM(svid)
}

// burn answers a redemption whose nonce was consumed and whose guest received no
// exchange SVID. status is the class the underlying fault maps to and class is
// the [classReferenceTypeDenied] family value that names it in the log.
//
// It exists because [Service.deny] would tell the wrong story. A denial means the
// presentation was refused and the nonce is still whatever it was; this means the
// presentation was accepted, the nonce is spent, and the failure is on this side.
// So the answer carries [codeNonceConsumedWithoutSVID] instead of the code its
// status would otherwise get, and the record carries outcome=burned and a failure
// class. The guest must obtain a fresh nonce from an operator; no retry of this
// one can ever succeed, and the distinct code is what tells it so, because a 500
// or a 503 alone is indistinguishable from a fault worth waiting out.
//
// The log record is the operator's alert surface, and its message is fixed for
// that reason: "nonce consumed but no exchange SVID was issued" states the whole
// event, and the nonce ID, the instance UUID, and the failure class say which
// nonce, which guest, and what to fix. The reason is the wrapped error text,
// which carries no material: the presented secret is a [nonce.Secret] and the
// exchange key never leaves [exchangeKeyPEM], and both redact themselves through
// every formatting path.
func (s *Service) burn(
	r *http.Request,
	w http.ResponseWriter,
	consumed nonce.Record,
	status int,
	class string,
	err error,
) {
	ctx := r.Context()

	s.logger.ErrorContext(ctx, "nonce consumed but no exchange SVID was issued",
		fieldOperation, operationRedeem,
		fieldOutcome, "burned",
		fieldNonceID, consumed.ID,
		fieldInstanceUUID, consumed.Instance,
		fieldProject, consumed.Project,
		fieldFailureClass, class,
		fieldPeerAddress, r.RemoteAddr,
		fieldHTTPStatus, status,
		fieldCode, codeNonceConsumedWithoutSVID,
		fieldReason, err.Error(),
	)

	_ = s.writeJSON(ctx, w, status, errorResponse{Error: codeNonceConsumedWithoutSVID})
}

// clearBootstrap empties the bootstrap key after a redemption has committed.
//
// A failure here does not fail the redemption. The consume is already
// committed, so what remains in the instance configuration is a value that no
// longer redeems; reporting a failure would invite a retry that can only be
// refused as already used. The event is logged at error level so the live run
// records the leftover.
func (s *Service) clearBootstrap(ctx context.Context, id nonce.NonceID, live attestor.InstanceRecord) {
	if err := s.minter.Clear(ctx, live.Project, live.Name); err != nil {
		s.logger.ErrorContext(ctx, "bootstrap key not cleared after redemption committed",
			fieldOperation, operationRedeem,
			fieldNonceID, id,
			fieldInstanceUUID, live.UUID,
			fieldInstanceName, live.Name,
			fieldProject, live.Project,
			fieldReason, err.Error(),
		)

		return
	}

	s.logger.InfoContext(ctx, "bootstrap key cleared",
		fieldOperation, operationRedeem,
		fieldNonceID, id,
		fieldInstanceUUID, live.UUID,
		fieldInstanceName, live.Name,
		fieldProject, live.Project,
	)
}

// requirePost answers a non-POST request with the uniform 405 body and reports
// whether the caller may continue.
func (s *Service) requirePost(w http.ResponseWriter, r *http.Request, operation string) bool {
	if r.Method == http.MethodPost {
		return true
	}

	w.Header().Set("Allow", http.MethodPost)
	s.refuse(r, w, operation, "", "",
		http.StatusMethodNotAllowed, codeMethodNotAllowed, "method "+r.Method+" is not allowed")

	return false
}

// authorizeMint reports whether the request presented the operator bearer
// token, and refuses it with 401 if it did not.
//
// The presentation is hashed and compared against the configured digest in
// constant time. Hashing first is what makes the comparison safe: both sides are
// then a fixed 32 bytes, so neither the length of the presented token nor the
// position of its first wrong byte is observable, and a missing header costs
// exactly what a wrong token costs.
//
// The refusal is logged with the peer address, because a probe against this
// endpoint is the first thing an operator needs to see, and never with the
// presented value.
func (s *Service) authorizeMint(w http.ResponseWriter, r *http.Request) bool {
	presented := sha256.Sum256([]byte(bearerToken(r.Header.Get(headerAuthorization))))
	if subtle.ConstantTimeCompare(presented[:], s.mintTokenDigest[:]) == 1 {
		return true
	}

	w.Header().Set(headerAuthenticate, bearerChallenge)
	s.refuse(r, w, operationMint, "", "",
		http.StatusUnauthorized, codeUnauthorized, "operator bearer token missing or not accepted")

	return false
}

// deny maps a core or adapter failure onto the documented status and answers
// with the uniform body. Every denial is logged with its reason, so the live
// run has a decision record for each case, and no reason ever carries secret
// material: the presented secret is a [nonce.Secret], which redacts itself.
func (s *Service) deny(
	r *http.Request,
	w http.ResponseWriter,
	operation string,
	id nonce.NonceID,
	instanceUUID attestor.InstanceUUID,
	err error,
) {
	status, code := failureStatus(err)
	s.refuse(r, w, operation, id, instanceUUID, status, code, err.Error())
}

// refuse logs one refusal and writes the uniform body. A 5xx is a fault an
// operator must look at, so it is logged at error level; a 4xx is an expected
// answer and is logged at warn level.
//
// Every refusal records the peer address. It is the only thing this service
// knows about who asked, and a rejected mint or a rejected nonce is exactly the
// event an operator has to attribute.
func (s *Service) refuse(
	r *http.Request,
	w http.ResponseWriter,
	operation string,
	id nonce.NonceID,
	instanceUUID attestor.InstanceUUID,
	status int,
	code string,
	reason string,
) {
	ctx := r.Context()
	record := []any{
		fieldOperation, operation,
		fieldOutcome, "denied",
		fieldNonceID, id,
		fieldInstanceUUID, instanceUUID,
		fieldPeerAddress, r.RemoteAddr,
		fieldHTTPStatus, status,
		fieldCode, code,
		fieldReason, reason,
	}

	if status >= http.StatusInternalServerError {
		s.logger.ErrorContext(ctx, "bootstrap request failed", record...)
	} else {
		s.logger.WarnContext(ctx, "bootstrap request denied", record...)
	}

	_ = s.writeJSON(ctx, w, status, errorResponse{Error: code})
}

// writeJSON writes one JSON document with the given status and reports whether
// the body reached the caller. A failure is logged here; whether it also has to
// be compensated is the caller's decision.
func (s *Service) writeJSON(ctx context.Context, w http.ResponseWriter, status int, body any) error {
	w.Header().Set("Content-Type", contentTypeJSON)
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(body); err != nil {
		s.logger.ErrorContext(ctx, "write response body", fieldHTTPStatus, status, fieldReason, err.Error())

		return fmt.Errorf("write response body: %w", err)
	}

	return nil
}

// bearerToken returns the credentials of a bearer authorization header, or the
// empty string for a missing header or any other scheme. The caller hashes the
// result either way, so an absent token follows the same path as a wrong one.
func bearerToken(header string) string {
	scheme, credentials, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, bearerScheme) {
		return ""
	}

	return strings.TrimSpace(credentials)
}

// decodeRequest reads one bounded JSON object into dest. The body limit is
// enforced with [net/http.MaxBytesReader], so an oversized body is refused
// instead of buffered.
//
// Unknown fields are refused. A request this service does not fully understand
// is a request it must not half-apply: silently dropping an unrecognised field
// is how a security parameter such as ttl_seconds came to be advertised and
// ignored, and a caller is better served by a 400 than by an answer that looks
// like agreement.
func decodeRequest(w http.ResponseWriter, r *http.Request, dest any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBytes))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(dest); err != nil {
		return fmt.Errorf("decode request body: %w", err)
	}

	return nil
}

// classifyLookup separates a lifecycle answer from a store fault on the binding
// lookup. A store that already named the lifecycle outcome keeps its sentinel;
// anything else becomes [nonce.ErrStoreUnavailable], so a broken backend is
// never reported as a refused nonce.
func classifyLookup(id nonce.NonceID, err error) error {
	if errors.Is(err, nonce.ErrNonceNotFound) {
		return err
	}

	return fmt.Errorf("%w: look up nonce %s: %w", nonce.ErrStoreUnavailable, id, err)
}

// failureStatus maps a failure onto its documented status and code. The table
// is the one in the package documentation.
//
// The backend classes are matched before the store and writer wrappers on
// purpose: the lifecycle core wraps a writer failure in
// [nonce.ErrWriterUnavailable] while keeping the class the adapter gave it, so
// an Incus credential refusal must not be laundered into a 503 that invites a
// retry it can never survive.
func failureStatus(err error) (int, string) {
	switch {
	case errors.Is(err, nonce.ErrNonceNotFound), errors.Is(err, nonce.ErrSecretMismatch):
		return http.StatusUnauthorized, codeUnauthorized

	case errors.Is(err, nonce.ErrNonceExpired),
		errors.Is(err, nonce.ErrNonceAlreadyUsed),
		errors.Is(err, nonce.ErrInstanceMismatch),
		errors.Is(err, nonce.ErrGenerationChanged),
		errors.Is(err, attestor.ErrInstanceNotFound),
		errors.Is(err, attestor.ErrAmbiguousReference),
		errors.Is(err, attestor.ErrGenerationMismatch),
		errors.Is(err, attestor.ErrUnusableRecord):
		return http.StatusConflict, codeConflict

	case errors.Is(err, attestor.ErrInvalidReference):
		return http.StatusBadRequest, codeInvalidRequest

	case errors.Is(err, attestor.ErrBackendUnauthorized), errors.Is(err, attestor.ErrBackendPermanent):
		return http.StatusInternalServerError, codeInternal

	case errors.Is(err, attestor.ErrBackendUnavailable),
		errors.Is(err, nonce.ErrStoreUnavailable),
		errors.Is(err, nonce.ErrWriterUnavailable):
		return http.StatusServiceUnavailable, codeUnavailable

	default:
		return http.StatusInternalServerError, codeInternal
	}
}

// exchangeFailure maps a Broker API failure onto its status and its log failure
// class. Every outcome is a 5xx, because by the time this mapping is consulted
// the guest has done everything right and the nonce is gone.
//
// It returns no body code, because there is only one: every failure here answers
// [codeNonceConsumedWithoutSVID]. The status still carries the split between what
// an operator must fix and what may clear on its own. A denial means the host-side
// configuration is wrong — the reference type is outside the agent's broker
// allowlist, or no registration entry matches incus:uuid:<uuid> for the exchange
// SPIFFE ID — and no amount of retrying by a guest will change that, so it answers
// 500. A transport failure, a timeout, and an empty stream are conditions that
// pass, so they answer 503 and invite the operator to mint again once the broker
// socket is back. Neither invites a retry of the burned nonce: the code forbids
// that, whatever the status.
//
// [broker.ErrReferenceTypeDenied] is matched before [broker.ErrPermissionDenied]
// because it wraps it, and it is the one denial the adapter can attribute.
func exchangeFailure(err error) (int, string) {
	switch {
	case errors.Is(err, broker.ErrReferenceTypeDenied):
		return http.StatusInternalServerError, classReferenceTypeDenied

	case errors.Is(err, broker.ErrPermissionDenied):
		return http.StatusInternalServerError, classPermissionDenied

	case errors.Is(err, broker.ErrInvalidRequest):
		return http.StatusInternalServerError, classInvalidRequest

	case errors.Is(err, broker.ErrTimeout):
		return http.StatusServiceUnavailable, classTimeout

	case errors.Is(err, broker.ErrTransport):
		return http.StatusServiceUnavailable, classTransport

	case errors.Is(err, broker.ErrNoSVID):
		return http.StatusServiceUnavailable, classNoSVID

	case errors.Is(err, errExchangeMaterial):
		return http.StatusInternalServerError, classMaterialInvalid

	default:
		return http.StatusInternalServerError, classUnknown
	}
}

// exchangePEM converts one Broker-delivered SVID out of DER into the PEM triple a
// SPIRE agent reads: an x509pop certificate chain, its PKCS#8 key, and the trust
// bundle. The leaf's NotAfter becomes the material's expiry, which is the only
// deadline the guest can act on.
//
// The private key is moved, never inspected. Its DER is wrapped in a PEM block
// and handed to [newExchangeKeyPEM] without being parsed, because parsing it
// would put a second copy of the key in this process to learn something the
// adapter already documents. Every failure here names a structural fault and
// never any part of the material.
func exchangePEM(svid broker.X509SVID) (exchangeMaterial, error) {
	chain, err := x509.ParseCertificates(svid.ChainDER)
	if err != nil {
		return exchangeMaterial{}, fmt.Errorf("%w: parse certificate chain: %w", errExchangeMaterial, err)
	}

	if len(chain) == 0 {
		return exchangeMaterial{}, fmt.Errorf("%w: the certificate chain is empty", errExchangeMaterial)
	}

	bundle, err := x509.ParseCertificates(svid.BundleDER)
	if err != nil {
		return exchangeMaterial{}, fmt.Errorf("%w: parse trust bundle: %w", errExchangeMaterial, err)
	}

	if len(bundle) == 0 {
		return exchangeMaterial{}, fmt.Errorf("%w: the trust bundle is empty", errExchangeMaterial)
	}

	key := pem.EncodeToMemory(&pem.Block{Type: pemTypePrivateKey, Headers: nil, Bytes: svid.KeyDER})
	if len(svid.KeyDER) == 0 || key == nil {
		return exchangeMaterial{}, fmt.Errorf("%w: no usable private key was delivered", errExchangeMaterial)
	}

	return exchangeMaterial{
		ID:        svid.ID,
		ChainPEM:  encodeCertificatesPEM(chain),
		BundlePEM: encodeCertificatesPEM(bundle),
		Key:       newExchangeKeyPEM(key),
		ExpiresAt: chain[0].NotAfter,
	}, nil
}

// encodeCertificatesPEM concatenates certificates as PEM blocks in the order
// given, which for a chain means leaf first.
func encodeCertificatesPEM(certificates []*x509.Certificate) string {
	var encoded strings.Builder

	for _, certificate := range certificates {
		block := &pem.Block{Type: pemTypeCertificate, Headers: nil, Bytes: certificate.Raw}
		// A strings.Builder never fails a write.
		_ = pem.Encode(&encoded, block)
	}

	return encoded.String()
}

// ReaperConfig carries the collaborators of a [Reaper]. Every field is required;
// composition happens in main.
type ReaperConfig struct {
	// Reader resolves a bound UUID to the live instance record, which is the
	// only source of the instance name a clear can be addressed to.
	Reader attestor.InstanceReader
	// Expired lists the records whose TTL elapsed unredeemed.
	Expired expiredLister
	// Withdrawer clears the bootstrap key and drops the record.
	Withdrawer nonceWithdrawer
	// Logger receives one record per withdrawal and per failure.
	Logger *slog.Logger
	// Interval is the period between sweeps.
	Interval time.Duration
	// Timeout bounds one sweep, including every Incus call it makes.
	Timeout time.Duration
	// Grace is how long past expiry a record is left alone before it is
	// withdrawn. It may be zero.
	Grace time.Duration
}

// Reaper withdraws nonces that expired without being redeemed.
//
// It exists because expiry alone does not remove anything: a nonce that nobody
// redeems stops being redeemable, but its secret stays readable in the guest's
// configuration key and its record stays in the store. Both accumulate for as
// long as the process lives, and the readable value is a bearer credential that
// simply stopped working.
//
// Sweeping is safe against a concurrent redemption for two reasons that hold
// together. A redemption can only commit while the nonce is unexpired, and a
// sweep only considers records that are already expired, so the two windows do
// not overlap. Any redemption that committed just before expiry is visible to
// the sweep, because a [nonce.Store] serialises its consume against its reads,
// and the core refuses to withdraw a consumed record. A clear that fails is
// therefore never compensated by dropping the record: the record stays, and the
// next tick tries again.
//
// A record is not withdrawn the instant it expires. Grace keeps it for a while
// longer, because the documented answer for a nonce that expired is 409 and the
// answer for a nonce that no longer exists is 401: withdrawing immediately would
// turn the first into the second and cost an operator, and the live run, the
// difference between "too late" and "never existed". The secret in the
// configuration key stops working at expiry either way; grace bounds how long
// the dead value lingers, it does not extend what it can do.
type Reaper struct {
	// reader resolves a bound UUID to the live instance record.
	reader attestor.InstanceReader
	// expired lists the records whose TTL elapsed unredeemed.
	expired expiredLister
	// withdrawer clears the bootstrap key and drops the record.
	withdrawer nonceWithdrawer
	// logger receives one record per withdrawal and per failure.
	logger *slog.Logger
	// interval is the period between sweeps.
	interval time.Duration
	// timeout bounds one sweep.
	timeout time.Duration
	// grace is how long past expiry a record is left alone.
	grace time.Duration
}

// NewReaper validates cfg and returns a concrete [Reaper].
func NewReaper(cfg ReaperConfig) (*Reaper, error) {
	switch {
	case cfg.Reader == nil:
		return nil, errors.New("broker: reaper requires an instance reader")
	case cfg.Expired == nil:
		return nil, errors.New("broker: reaper requires an expired-record lister")
	case cfg.Withdrawer == nil:
		return nil, errors.New("broker: reaper requires a nonce withdrawer")
	case cfg.Logger == nil:
		return nil, errors.New("broker: reaper requires a logger")
	case cfg.Interval <= 0:
		return nil, errors.New("broker: reaper requires a positive interval")
	case cfg.Timeout <= 0:
		return nil, errors.New("broker: reaper requires a positive timeout")
	case cfg.Grace < 0:
		return nil, errors.New("broker: reaper requires a non-negative grace period")
	}

	return &Reaper{
		reader:     cfg.Reader,
		expired:    cfg.Expired,
		withdrawer: cfg.Withdrawer,
		logger:     cfg.Logger,
		interval:   cfg.Interval,
		timeout:    cfg.Timeout,
		grace:      cfg.Grace,
	}, nil
}

// Run sweeps every interval until ctx is done, then returns. It is meant to be
// started in its own goroutine alongside the listener and to stop with it.
func (rp *Reaper) Run(ctx context.Context) {
	ticker := time.NewTicker(rp.interval)
	defer ticker.Stop()

	rp.logger.InfoContext(ctx, "expired nonce reaper started",
		fieldOperation, operationReap,
		"interval", rp.interval.String(),
		"timeout", rp.timeout.String(),
		"grace", rp.grace.String(),
	)

	for {
		select {
		case <-ctx.Done():
			rp.logger.InfoContext(ctx, "expired nonce reaper stopped", fieldOperation, operationReap)

			return

		case <-ticker.C:
			rp.sweep(ctx)
		}
	}
}

// sweep withdraws every expired unredeemed nonce it can, under its own timeout
// so one unreachable Incus cannot stall the reaper forever. A record it fails on
// is left in place for the next tick.
func (rp *Reaper) sweep(ctx context.Context) {
	bounded, cancel := context.WithTimeout(ctx, rp.timeout)
	defer cancel()

	expired, err := rp.expired.ListExpired(bounded, time.Now().Add(-rp.grace))
	if err != nil {
		rp.logger.ErrorContext(bounded, "expired nonces not listed",
			fieldOperation, operationReap,
			fieldReason, err.Error(),
		)

		return
	}

	for _, record := range expired {
		rp.withdraw(bounded, record)
	}
}

// withdraw clears the bootstrap key of one expired nonce and deletes its record.
//
// The instance name is re-resolved through the read path first, because the
// bootstrap-writer credential cannot resolve it (P5) and a name is reusable
// after a delete and recreate (P6): clearing a stale name would empty the key of
// whatever instance holds that name now. An instance that no longer exists took
// its configuration with it, so only the record is dropped.
func (rp *Reaper) withdraw(ctx context.Context, record nonce.Record) {
	fields := []any{
		fieldOperation, operationReap,
		fieldNonceID, record.ID,
		fieldInstanceUUID, record.Instance,
		fieldProject, record.Project,
		fieldExpiresAt, record.ExpiresAt,
	}

	live, err := rp.reader.ReadInstanceByUUID(ctx, record.Instance, record.Project)
	if err != nil {
		if errors.Is(err, attestor.ErrInstanceNotFound) {
			rp.discard(ctx, record.ID, fields)

			return
		}

		rp.logger.ErrorContext(ctx, "expired nonce not withdrawn; retrying on the next sweep",
			append(fields, fieldReason, err.Error())...)

		return
	}

	fields = append(fields, "instance_name", live.Name)

	switch err := rp.withdrawer.Revoke(ctx, record.ID, live.Project, live.Name); {
	case err == nil:
		rp.logger.InfoContext(ctx, "expired nonce withdrawn", fields...)

	case errors.Is(err, nonce.ErrNonceAlreadyUsed), errors.Is(err, nonce.ErrNonceNotFound):
		rp.logger.InfoContext(ctx, "expired nonce needed no withdrawal",
			append(fields, fieldReason, err.Error())...)

	default:
		rp.logger.ErrorContext(ctx, "expired nonce not withdrawn; retrying on the next sweep",
			append(fields, fieldReason, err.Error())...)
	}
}

// discard drops the record of an expired nonce whose instance is gone. There is
// no configuration left to clear, and retrying the read forever would be the
// only alternative.
func (rp *Reaper) discard(ctx context.Context, id nonce.NonceID, fields []any) {
	if err := rp.withdrawer.Discard(ctx, id); err != nil {
		rp.logger.ErrorContext(ctx, "expired nonce record not dropped; retrying on the next sweep",
			append(fields, fieldReason, err.Error())...)

		return
	}

	rp.logger.WarnContext(ctx, "expired nonce record dropped: its instance no longer exists", fields...)
}

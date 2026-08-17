// Package main implements incus-spiffe-broker, the guest-facing bootstrap
// service that mints and redeems one-time Incus instance nonces.
//
// The binary is a driving adapter. It owns no trust rules: it composes the
// read-only Incus identity adapter
// (github.com/componere/incusos-spire/internal/incus/identity), the
// write-only bootstrap configuration adapter
// (github.com/componere/incusos-spire/internal/incus/bootstrap), the in-memory
// nonce store (github.com/componere/incusos-spire/internal/nonce/memory), the
// nonce lifecycle core (github.com/componere/incusos-spire/internal/nonce),
// and the pure selector core
// (github.com/componere/incusos-spire/internal/attestor). Composition happens
// in main only; the HTTP surface talks to ports.
//
// # Decision D1-broker-binary: this binary stays separate from incus-attestor
//
// Appendix C asks whether the guest-facing broker merges with the
// cmd/incus-attestor plugin binary. The answer is no: they stay separate
// programs.
//
// The two carry different Incus credentials and sit on different trust
// boundaries. incus-attestor is a SPIRE agent plugin, executed by the agent
// over the go-plugin transport, holding the read-only spike-attestor-ro
// credential, and reachable only by the agent that spawned it. This service is
// a network listener on incusbr0 that holds the spike-bootstrap-writer
// credential, the one credential in the system that can write instance
// configuration. Merging them would put a config-write credential inside a
// process that every SPIRE agent loads, and would put a network listener inside
// a plugin whose lifetime the agent controls. P5 established that the two
// credentials must never be merged; a merged binary keeps that separation only
// by convention, while two binaries keep it by construction.
//
// The label is D1-broker-binary rather than plain "D1" on purpose: P7 evidence
// already used "D1" for the plugin delivery mechanism, and the two decisions
// are unrelated.
//
// # Endpoints
//
// Both endpoints are POST, take a JSON object, answer with a JSON object, and
// are served over TLS with a spike-issued server certificate. Neither accepts
// an unknown field: a body this service does not fully understand is answered
// with 400 rather than half-applied.
//
//	POST /v1alpha1/nonce   operator path: provision one guest, bearer token required
//	POST /v1alpha1/redeem  guest path: redeem the value read from the config key
//
// The operator request names the instance by UUID, may name a project, and may
// ask for a shorter lifetime than the configured default:
//
//	Authorization: Bearer <operator token>
//	{"instance_uuid":"<volatile.uuid>","project":"<project>","ttl_seconds":120}
//
// ttl_seconds is optional. It must be positive and must not exceed
// -max-nonce-ttl, which defaults to -nonce-ttl; a value outside that range is
// refused with 400 rather than clamped, because an operator who asked for a
// five-second window and silently received ten minutes has been told something
// untrue about a bearer credential. The applied lifetime is always readable in
// the answer's expires_at.
//
// The service resolves that UUID through the read-only path, exactly as the
// attestor does, and fails closed on a UUID that resolves to zero instances or
// to more than one. It then mints against the freshly resolved instance name,
// because Incus instance names are reusable after a delete and recreate (P6)
// and a cached name can address a different instance. The answer is:
//
//	{"nonce_id":"<id>","expires_at":"<RFC3339>","instance_uuid":"<uuid>",
//	 "instance_name":"<name>","generation":"<generation>","project":"<project>"}
//
// The operator answer deliberately carries no nonce secret. The secret reaches
// exactly one destination, the guest-readable instance configuration key
// user.spiffe-bootstrap, so possession of the secret is evidence that the
// caller could read that key from inside the bound instance. An operator who
// could also read the secret out of an HTTP response would be a second copy of
// a bearer credential, and a broker log, a proxy, or a shell history would
// become a place the secret can leak from.
//
// The guest request presents what the guest read out of the configuration key:
//
//	{"nonce_id":"<id>","nonce":"<secret>"}
//
// Those are the first two fields of the bootstrap payload. A guest may forward
// the document it read verbatim, so broker_url and broker_fingerprint are
// accepted and ignored, and every other field is refused with 400. That
// includes instance_uuid: the service resolves only the UUID the nonce is bound
// to server-side (plan step 5), so a caller-claimed identity is not merely
// disregarded, it is not accepted at all. A guest cannot read volatile.uuid
// through /dev/incus/sock and therefore cannot state its own identity; a guest
// that states someone else's identity is not believed.
//
// On success the service redeems the nonce, clears the bootstrap key, and
// answers with the derived selectors for the bound instance:
//
//	{"nonce_id":"<id>","instance_uuid":"<uuid>","instance_name":"<name>",
//	 "generation":"<generation>","project":"<project>","selectors":["incus:uuid:<uuid>", ...]}
//
// P9 replaces that body with an exchange SVID; the selector list exists so the
// P8 live run has an observable, secret-free result to record.
//
// # Authentication, and why only one endpoint has it
//
// The mint endpoint requires an operator bearer token, read at startup from
// -mint-token-file (or INCUS_SPIFFE_BROKER_MINT_TOKEN_FILE). The token must be
// at least 32 characters and the process refuses to start without it: there is
// no unauthenticated mode and no insecure default. Only the SHA-256 of the token
// is kept, so the running service never holds the credential, and a presentation
// is hashed before it is compared, which makes the comparison constant time over
// two fixed-length values. A missing or wrong token answers 401 with the uniform
// body and is logged with the peer address and never with the presented value.
// The check runs before the request is decoded and before the read path is
// touched, so an unauthenticated caller reaches neither Incus credential.
//
// The redemption endpoint is deliberately unauthenticated, and that asymmetry is
// the design, not an omission:
//
//   - Minting is a privileged operation on someone else's instance. It spends
//     the read-only credential to resolve a UUID and the write-only credential
//     to place a bearer secret in a guest's configuration. Anyone who can reach
//     the listener could otherwise provision, and repeatedly overwrite, the
//     bootstrap key of any instance in the project whose UUID they know, and a
//     UUID is not a secret.
//   - Redeeming is the presentation of a credential, and the nonce is that
//     credential. The guest has nothing else: it cannot read volatile.uuid
//     through /dev/incus/sock, it has no operator token, and the only thing it
//     knows is what appeared in its own configuration key. Requiring a second
//     credential to protect the first would need that second credential to be
//     provisioned by the very channel this exchange exists to establish.
//   - The redemption path is bounded by what a nonce is worth: it is single use,
//     short lived, bound to one instance UUID and generation, and its secret is
//     never returned to anyone. A caller who presents a nonce it stole gains
//     exactly what the theft already gave it, and the atomic consume means the
//     legitimate guest then fails loudly rather than silently sharing an
//     identity. Risk R10 records that residual exposure.
//
// What the asymmetry does not fix is finding SEC-009: the read-only credential
// can read user.spiffe-bootstrap for every instance in the project, so a holder
// of that credential can steal a nonce before its guest redeems it. That is an
// architecture finding, recorded as such, and no endpoint check in this binary
// can close it.
//
// # Failure mapping
//
// Every failure answers with one uniform body, {"error":"<code>"}, whose code
// names the status class and never names the cause. Detail goes to the log, not
// to the caller.
//
//	sentinel                            status  code
//	nonce.ErrNonceNotFound                 401  unauthorized
//	nonce.ErrSecretMismatch                401  unauthorized
//	nonce.ErrNonceExpired                  409  conflict
//	nonce.ErrNonceAlreadyUsed              409  conflict
//	nonce.ErrInstanceMismatch              409  conflict
//	nonce.ErrGenerationChanged             409  conflict
//	attestor.ErrInstanceNotFound           409  conflict
//	attestor.ErrAmbiguousReference         409  conflict
//	attestor.ErrGenerationMismatch         409  conflict
//	attestor.ErrUnusableRecord             409  conflict
//	attestor.ErrInvalidReference           400  invalid_request
//	attestor.ErrBackendUnauthorized        500  internal
//	attestor.ErrBackendPermanent           500  internal
//	attestor.ErrBackendUnavailable         503  unavailable
//	nonce.ErrStoreUnavailable              503  unavailable
//	nonce.ErrWriterUnavailable             503  unavailable
//	missing or wrong operator token        401  unauthorized
//	malformed or oversized request body    400  invalid_request
//	unknown field in a request body        400  invalid_request
//	ttl_seconds outside its range          400  invalid_request
//	any method other than POST             405  method_not_allowed
//	anything else                          500  internal
//
// The last six rows are this service's own additions; the rest is the mapping
// P8 fixed. attestor.ErrGenerationMismatch, attestor.ErrUnusableRecord, and
// attestor.ErrInvalidReference are reachable only through selector derivation
// after a successful redemption, and they join the class they belong to.
//
// Three rules constrain the table. The 401 bodies for an unknown nonce and for a
// wrong secret are byte-identical, so a caller cannot use the broker to
// enumerate live nonce IDs. A refused operator token answers with the same body,
// so the mint endpoint cannot be used to probe anything either; only the log
// distinguishes the cases, and it names the peer address rather than the
// credential. And the backend classes are matched before the
// nonce.ErrStoreUnavailable and nonce.ErrWriterUnavailable wrappers, because
// the lifecycle core wraps a writer failure in nonce.ErrWriterUnavailable
// without discarding the class the adapter gave it: an Incus credential refusal
// stays a 500 an operator must fix, and only a genuinely transient fault
// answers 503 and invites a retry.
//
// # Secret handling
//
// Appendix D applies in full. This package never calls nonce.Secret.Reveal:
// the only reveal in the system is the marshalling of the bootstrap payload
// inside the nonce package, on its way to the instance configuration key. Logs
// carry nonce IDs, instance UUIDs, generations, project and instance names,
// status codes, and outcomes. A presented secret is converted to a
// nonce.Secret, which redacts itself through every formatting path, and the raw
// request field is zeroed as soon as that conversion happens.
//
// # Ordering the live run depends on
//
// A redemption commits before the bootstrap key is cleared, which is what makes
// a crash between the two harmless: the instance configuration keeps a value
// that no longer redeems, instead of a cleared key over a still-reusable
// credential. A failure to clear therefore does not fail the redemption; it is
// logged at error level and the caller still receives its answer.
//
// A mint whose operator never learned the nonce ID is withdrawn again. The
// bootstrap key is already written by the time the answer is composed, so a
// cancelled request context or an undeliverable body would otherwise leave a
// live bearer credential in a guest's configuration that nobody is waiting for.
// The withdrawal clears the key and deletes the record on a context detached
// from the caller's, because the caller is the thing that failed, and it is
// recorded with the nonce ID. If the guest redeemed in between, the core refuses
// the withdrawal and that refusal is recorded instead: the redemption path owns
// the clear for a consumed nonce.
//
// # Reaping what nobody redeemed
//
// Expiry alone removes nothing. A nonce that no guest redeems stops being
// redeemable at its expires_at, but its secret stays readable in
// user.spiffe-bootstrap and its record stays in the store, both for as long as
// the process lives. The broker therefore sweeps every -reap-interval (default
// one minute) under a -reap-timeout bound (default thirty seconds): it lists
// the expired, unconsumed records, re-resolves each bound UUID through the read
// path, clears the bootstrap key, and only then deletes the record. Every
// withdrawal is logged with the nonce ID and the instance UUID.
//
// A record is not withdrawn the instant it expires. -reap-grace (default two
// minutes) keeps it a while longer, because the documented answer for an expired
// nonce is 409 and the answer for a nonce that no longer exists is 401:
// withdrawing at expires_at would turn the first into the second and cost a
// caller the difference between "too late" and "never existed". The value in the
// configuration key stops working at expiry either way, so grace bounds how long
// a dead secret lingers without extending what it can do.
//
// The sweep is safe against a concurrent redemption for two reasons that hold
// together. A redemption can only commit while the nonce is unexpired and the
// sweep only considers records that are already expired, so the windows do not
// overlap; and any redemption that committed just before expiry is visible to
// the sweep, because the store serialises its consume against its reads and the
// core refuses to withdraw a consumed record. Ordering matters for the same
// reason it does at mint time: the key is cleared before the record is deleted,
// so a failed clear leaves the record, and therefore the retry handle, in place
// for the next tick. An instance that no longer exists took its configuration
// with it, so only the record is dropped.
//
// Records of nonces that were redeemed are left alone entirely, at any age.
// Their configuration value can no longer redeem, and the record is what makes a
// replay answer 409 rather than 401. Their retention is therefore still
// unbounded over the life of the process; SEC-002's pruning half is closed for
// the population that holds a live secret, not for consumed records.
package main

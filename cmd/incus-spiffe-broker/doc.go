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
// are served over TLS with a spike-issued server certificate.
//
//	POST /v1alpha1/nonce   operator path: provision one guest
//	POST /v1alpha1/redeem  guest path: redeem the value read from the config key
//
// The operator request names the instance by UUID and may name a project:
//
//	{"instance_uuid":"<volatile.uuid>","project":"<project>"}
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
// Those are the first two fields of the bootstrap payload, so a guest can
// forward the document it read verbatim; broker_url and broker_fingerprint are
// ignored. Any other field is ignored as well, and that includes
// instance_uuid: the service resolves only the UUID the nonce is bound to
// server-side (plan step 5). A guest cannot read volatile.uuid through
// /dev/incus/sock and therefore cannot state its own identity; a guest that
// states someone else's identity is not believed.
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
//	malformed or oversized request body    400  invalid_request
//	any method other than POST             405  method_not_allowed
//	anything else                          500  internal
//
// The last four rows are this service's own additions; the rest is the mapping
// P8 fixed. attestor.ErrGenerationMismatch, attestor.ErrUnusableRecord, and
// attestor.ErrInvalidReference are reachable only through selector derivation
// after a successful redemption, and they join the class they belong to.
//
// Two rules constrain the table. The 401 bodies for an unknown nonce and for a
// wrong secret are byte-identical, so a caller cannot use the broker to
// enumerate live nonce IDs. And the backend classes are matched before the
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
package main

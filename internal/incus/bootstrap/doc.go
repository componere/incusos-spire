// Package bootstrap is the write-only Incus adapter for the single instance
// config key user.spiffe-bootstrap.
//
// The package performs exactly two operations, each one raw PATCH:
//
//	PATCH /1.0/instances/<name>?project=<project>   {"config":{"user.spiffe-bootstrap":"<payload>"}}   # set
//	PATCH /1.0/instances/<name>?project=<project>   {"config":{"user.spiffe-bootstrap":""}}            # clear
//
// There is no create, delete, exec, state-change, file, rename, or instance
// read operation in this package, and there never may be. The adapter must
// never write any volatile.* key, nor any config key other than
// [ConfigKey]; [ErrKeyNotAllowed] enforces that in code before a request is
// built.
//
// # Why a raw PATCH and not incus config set
//
// P5 measured the bootstrap-writer credential on the live host: it is denied
// every read in the managed project, including GET of the instance it is about
// to write. "incus config set" performs a read-modify-write and therefore
// additionally needs can_view, so it fails for this credential. A raw PATCH
// needs no client read because Incus merges the submitted config into the
// stored config server-side. Clearing uses the same PATCH with an empty value,
// which removes the key rather than storing an empty one.
//
// # The write target is a name, and the caller must re-resolve it
//
// The writer cannot translate a volatile.uuid into an instance name, because
// that is a read. The caller therefore supplies the name, resolved through the
// read-only path in internal/incus/identity. Instance names are reusable after
// delete and recreate (P6), so the composing service must re-resolve the name
// from the UUID immediately before every write, and keep the UUID plus
// volatile.uuid.generation as the identity anchor.
//
// # The allowlist is defence in depth, not the security boundary
//
// P5 proved that Incus 7.3 cannot express "may write one config key". The
// authorization scriptlet receives only (details, object, entitlement) and
// never the request body, and DELETE and PATCH share the can_edit entitlement,
// so the credential that can set user.spiffe-bootstrap can also write
// volatile.uuid, write volatile.uuid.generation, and delete the instance. That
// residual privilege is a property of the credential, not of this code. The
// allowlist here only guarantees that this adapter is not the thing that
// exercises it: a caller that reaches [Writer] with any other key leaves with
// [ErrKeyNotAllowed] and nothing on the wire.
//
// # Secret handling
//
// The payload carries a nonce value. Appendix D of the spike plan forbids that
// value from reaching any log, error, or evidence file. This package therefore
// logs nothing at all, never formats the payload into an error, and passes
// every server-supplied string through a redaction step before it can become
// part of an error, because an Incus error envelope can echo submitted
// content.
//
// # Credential isolation
//
// This package must not import internal/incus/identity. The two adapters carry
// different credentials, the read-only attestor identity and the bootstrap
// writer, and AGENTS.md A2 splits adapters by credential rather than by
// service. Sharing code between them would put both credentials behind one
// configuration surface.
//
// # Error taxonomy
//
// Backend failures reuse the sentinels of the read adapter so the composing
// service classifies both uniformly: [attestor.ErrBackendUnavailable] for a
// transient transport fault, which is the only class retried and only within a
// bounded budget, [attestor.ErrBackendUnauthorized] for HTTP 401 or 403, which
// is never retried, and [attestor.ErrBackendPermanent] for an unexpected
// status, a malformed or oversized body, an Incus error envelope, a failed
// operation, or a TLS pin failure. A local refusal ([ErrKeyNotAllowed],
// [ErrInvalidTarget], [ErrEmptyPayload]) is not a backend failure and carries
// no backend class.
//
// # The one GET that can exist
//
// On Incus 7.3 an instance PATCH is answered synchronously with an empty sync
// envelope, so a write is exactly one request. If a deployment answers with a
// background operation instead, treating HTTP 202 as success would report a
// write that may still fail, so the adapter waits it out with
// GET /1.0/operations/<id>/wait?timeout=<seconds>, bounded by whatever remains
// of the configured request timeout. That endpoint returns operation status
// only, never instance data, and Incus authorizes it on being a trusted client
// rather than on can_view, so it stays within a read-denied credential.
package bootstrap

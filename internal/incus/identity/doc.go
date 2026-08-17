// Package identity is the read-only Incus adapter for [attestor.InstanceReader].
//
// The package performs exactly two Incus operations and nothing else:
//
//   - GET /1.0/instances?recursion=1&project=<project>&filter=config.volatile.uuid eq <uuid>
//   - GET /1.0 for environment.server_name and environment.certificate_fingerprint
//
// Create, delete, exec, file, and state-change calls do not exist in this
// package, so the adapter code itself has no way to write instance config. That
// is A2 isolation of the driven side, and it is the whole of what this package
// contributes to trust rule 4.
//
// # Trust rule 4 is a deployment invariant, not a code guarantee
//
// REFERENCE_SCHEMA.md §3 rule 4 requires that no principal able to write
// instance config sits inside the attestation trust boundary. The keys
// volatile.uuid, volatile.uuid.generation, and volatile.base_image are writable
// through the ordinary config surface, so a config-write credential could spoof
// the identity the attestor exists to prove.
//
// This package neither enforces nor can enforce that rule. [NewReader] accepts
// any syntactically valid certificate and key, so an overprivileged credential
// configures successfully and reads work exactly as they would for a
// least-privilege one. The "attestor-ro" naming used in deployment
// configuration is a convention, and no test here establishes it. Absence of
// write methods in the adapter does not constrain what the principal behind the
// credential is allowed to do.
//
// Enforcement belongs to the Incus server-side authorization policy, managed as
// reviewed deployment configuration and bound to the expected client identity.
// Phase P5 measured the alternatives on the live host:
//
//   - A plain TLS certificate added with --restricted --projects <project> is a
//     full project operator. It was allowed to write every instance config key,
//     including volatile.uuid and security.privileged, and the read-only and
//     write-capable identities were indistinguishable across all 34 adversarial
//     cases. Project confinement held; intra-project confinement did not exist.
//   - A genuinely read-only, project-confined identity required an Incus
//     authorization scriptlet: the authorization.scriptlet server config key
//     routed through authorization.client.tls-restricted=scriptlet. Because
//     routing tls-restricted away from the tls driver stops Incus enforcing the
//     per-certificate project list, that scriptlet must re-implement project
//     confinement itself.
//
// Operators must supply and independently verify that policy. Configuring this
// package correctly is not evidence that rule 4 holds.
package identity

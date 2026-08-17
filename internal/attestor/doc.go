// Package attestor is the pure selector-derivation core for Incus workload
// attestation.
//
// The package performs no I/O. It holds the consumer-owned [InstanceReader]
// port (A1) and applies the frozen P6 trust rules to an [InstanceRecord] read
// through that port. Adapters in other packages implement the port; this
// package never imports an Incus client, [net/http], or a clock.
//
// Callers construct a [Deriver] with [NewDeriver] and invoke [Deriver.Derive]
// with a broker-submitted [Reference]. Successful derivation always returns
// the six frozen selectors in a deterministic order. Failures are wrapped so
// [errors.Is] matches the sentinel that names the trust-rule violation.
//
// # Trust rule 7 is an operational requirement on registration authoring
//
// REFERENCE_SCHEMA.md §3 rule 7 requires that incus:name never appears alone in
// a SPIRE registration entry. An Incus instance name is reusable: delete an
// instance and create a new one under the same name and the name selector
// matches a different workload. Only incus:uuid is a non-reusable anchor, and
// incus:generation pins the instance against rollback.
//
// This package cannot enforce that rule. [Deriver.Derive] always emits all six
// selectors, but a SPIRE registration entry may match any subset of what an
// attestation produces, and registration entries are authored outside this
// repository. There is no registration-entry type or validator in this scope,
// and no test here can prove an operator did not write a name-only entry.
//
// The requirement therefore lands on whoever authors registration entries:
// every entry that uses incus:name must also carry incus:uuid, and should carry
// incus:generation when rollback matters. Treat incus:name and incus:image as
// informational corroboration only.
package attestor

// Package main implements incus-attestor, the external SPIRE agent
// WorkloadAttestor plugin that attests Incus instances.
//
// The binary is a driving adapter only. It serves the SPIRE plugin SDK
// services spire.plugin.agent.workloadattestor.v1.WorkloadAttestor and
// spire.service.common.config.v1.Config over the go-plugin transport, decodes
// the agent's plugin_data HCL, builds the read-only Incus identity reader, and
// delegates every trust decision to the pure core in
// github.com/componere/incusos-spire/internal/attestor. It performs no
// derivation and calls no Incus API itself.
//
// SPIRE infers the selector type from the configured plugin name, so the
// plugin must be declared as WorkloadAttestor "incus" and returns unprefixed
// selector values such as uuid:<value>. SPIRE renders them as
// incus:uuid:<value>.
//
// # Two invariants this binary does not enforce
//
// Registration entries are authored outside this binary. The plugin always
// emits all six frozen selectors, but SPIRE matches an entry against any
// subset, so an operator can still author an entry whose only Incus selector
// is incus:name. Instance names are reusable after a delete and recreate, so
// every entry that uses incus:name must also carry incus:uuid
// (REFERENCE_SCHEMA.md §3 rule 7, an operational requirement).
//
// The privilege of the configured Incus credential is likewise a deployment
// invariant. Configure validates that client_cert_path and client_key_path
// load, not that the principal behind them is read-only and project-confined;
// that must come from the Incus server-side authorization policy. See the
// github.com/componere/incusos-spire/internal/incus/identity package
// documentation for the P5 measurements behind §3 rule 4.
package main

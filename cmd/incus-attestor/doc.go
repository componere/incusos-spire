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
package main

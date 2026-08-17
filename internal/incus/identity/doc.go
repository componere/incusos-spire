// Package identity is the read-only Incus adapter for [attestor.InstanceReader].
//
// The package performs exactly two Incus operations and nothing else:
//
//   - GET /1.0/instances?recursion=1&project=<project>&filter=config.volatile.uuid eq <uuid>
//   - GET /1.0 for environment.server_name and environment.certificate_fingerprint
//
// It links only the least-privilege attestor-ro credential. A principal that can
// write instance config must never sit inside the attestation trust boundary
// (REFERENCE_SCHEMA.md §3 rule 4): volatile.uuid, volatile.uuid.generation, and
// volatile.base_image are writable through the ordinary config surface, so a
// config-write credential could spoof the identity the attestor is supposed to
// prove. Create, delete, exec, file, and state-change calls do not exist in this
// package.
package identity

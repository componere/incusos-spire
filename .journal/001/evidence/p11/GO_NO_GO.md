# P11 Architecture Go/No-Go

## Decision

**NO-GO for production adoption of the current architecture.**

The spike proves the Incus-level direction is technically viable: the physical TPM establishes the host node, the v1.15.2 Broker API routes the Incus reference, `x509pop` establishes the guest node, and the standard guest Workload API issues workload identities. Adoption is blocked because three mandatory GO criteria are not satisfied. The direct import result also matches an explicit NO-GO trigger.

This decision rejects the current trust and lifecycle boundaries, not the demonstrated TPM-to-guest mechanism. No fallback architecture is silently adopted.

## Final criteria

| # | GO criterion | Verdict | Decision basis |
|---:|---|---|---|
| 1 | Physical-TPM G3, including endorsement-chain validation and no degraded host fallback | **PASS** | P0–P3 validate the Nuvoton endorsement chain, TPM-resident DevID, stock `tpm_devid` attestation, negative cases, restart/reboot continuity, and unchanged TPM state. P10 directly forced fresh post-reboot attestation. |
| 2 | H6 on pinned SPIRE v1.15.2 with all Broker failure-isolation behaviors | **PASS** | P7 proves the vendor reference type, external attestor routing, checksum gate, authorization and transport separation, missing-header rejection, empty/multiple UUID rejection, generation mismatch, and bounded backend failure. |
| 3 | Required P10 isolation cases; unused-bearer risk mitigated or explicitly accepted | **FAIL** | The lifecycle cases pass, but a deliberately transferred unused value returned A's exchange credential from B. The composed P8/P9 contract makes that credential sufficient to become A's derived guest node. Caller binding is unimplemented. P11 does **not** accept this High residual risk. |
| 4 | Import-safe anchor uniqueness or authoritative global uniqueness and reconciliation | **FAIL — explicit NO-GO trigger** | Supported export/import preserved `volatile.uuid`, `volatile.uuid.generation`, and `created_at`; after MAC deduplication, both instances ran concurrently with the same authoritative anchors. Multi-match rejection prevents silent selection but does not prevent the duplicate. Incus does not re-key or reject it, and no global uniqueness/reconciliation mechanism was proven. |
| 5 | Least-privilege result with residual over-grant judged acceptable | **FAIL** | The attestor credential is acceptably read-only. The smallest bootstrap-writer grant can mutate all instance config, forge both identity anchors, rename, and delete instances. The network-facing broker held this raw writer credential alongside the read credential, Broker socket, and its own authorized SVID. Method-level Go adapters do not constrain a compromised credential holder. P11 does **not** accept this authority. |
| 6 | Post-teardown TPM equality and trusted unlock | **PASS** | P11 deleted every recorded spike resource, rebooted the host, and re-ran the read-only inventory. Persistent handle `0x81000001`, NV indices `0x01C00002` and `0x01C0000A`, counts, hierarchy flags, and zero lockout counter match P0. Secure Boot, system trust, and TPM unlock for root and swap remain intact. |

A GO requires all six criteria. Criteria 3–5 fail; criterion 4 independently requires NO-GO under the source plan.

## Blocking contradictions

### 1. Supported import duplicates identity anchors

P10-ARCH-001 directly contradicts the assumption that every operation which creates another instance produces unique authoritative anchors. This is not the deferred real cluster-member migration case. It occurred through supported single-node export/import.

Required closure: reject import when its UUID or generation already exists, or re-key both values before the imported instance becomes visible. If neither is possible, implement and prove authoritative global uniqueness plus reconciliation across copy, restore, move, import, rename, and deletion. Repeat P10 cases 6, 8, and 9 after the change.

### 2. Bootstrap redemption authenticates possession, not the guest

Per-instance socket isolation prevents B from reading A's value through B's own guest API, but a copied unused value is portable. Short TTL, entropy, single use, and reaping reduce exposure; they do not bind redemption to guest-held proof or revoke an identity already issued.

Required closure: bind redemption to non-replayable guest-held proof whose verifier input arrives through an independently authenticated path. A CSR-style exchange should keep private keys in the guest, but a CSR alone does not close nonce theft unless the request is also bound to the intended guest. Repeat the P8/P10 wrong-instance, deliberate-transfer, replay, concurrency, expiry, restart, and stale-state cases.

### 3. The bootstrap writer violates the anchor trust model

Incus 7.3 cannot authorize one `user.*` key independently from `can_edit`. The resulting credential can rewrite `volatile.uuid` and generation, delete, and rename instances. Co-locating that credential with the guest-facing broker means one process compromise combines anchor mutation, authoritative instance reads, and SPIFFE issuance.

Required closure: keep raw config-write authority out of the network listener and outside the trust boundary that consumes Incus anchors. Prefer a provisioning-time administrative path or a separate narrowly exposed helper with a protocol that cannot mutate identity anchors. Split Incus read, Incus mutation, Broker API, and Workload API authorities; expose only required socket endpoints, never the host-agent state volume. Re-run P5 and the broker security review against the resulting process boundaries.

## Required pre-production work after blocker closure

These items did not independently trigger the decision but must be resolved before a future GO:

1. Provide a durable, independently authorized broker SVID source with supervised boot ordering and readiness; remove the spike relay.
2. Distribute overlapping current/next bootstrap authorities atomically and validate the authoritative server bundle before deleting cached agent state.
3. Choose and prove the guest node re-attestation lifecycle. Fresh credential per boot is insufficient for in-process `x509pop` re-attestation; retaining the exchange private key has a different exposure cost.
4. Integrate the external plugin into a digest-pinned image instead of a shared writable volume.
5. Re-run the Broker API contract on every SPIRE upgrade because the API is experimental.
6. Prove real cluster-member migration when a cluster exists. This remains an allowed conditional item and is separate from the blocking import result.

## Reconsideration gate

Reconsider production adoption only after all three blocking contradictions are closed in implementation and the targeted P5, P8, P9, and P10 checks pass. The physical-TPM and Broker feasibility results may be reused; the failed trust-boundary and import assumptions may not.

## Teardown result

P11 cleanup passed. The final host has no workloads, spike volumes, spike project, spike trust identities, recorded spike images, authorization hooks, or local spike credentials. The post-reboot TPM and Secure Boot baseline diff is empty. See [`teardown.txt`](./teardown.txt), [`tpm-diff.txt`](./tpm-diff.txt), and [`final-state.txt`](./final-state.txt).

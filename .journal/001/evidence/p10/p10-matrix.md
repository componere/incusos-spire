# P10 Adversarial and Lifecycle Matrix

This matrix summarizes the ten required P10 cases. It records decision inputs for P11; it does not make the final architecture adoption decision. “Observed” means directly observed unless the text explicitly says `[INFERENCE]`.

## Matrix

| Case | Expected | Observed | Verdict | Cleanup | Architecture effect | Source fragment |
|---|---|---|---|---|---|---|
| 1 — Host reboot | Host agent re-attests via `tpm_devid`; guests recover per P9 §4; TPM-unlock invariant re-verified | The original reboot loaded a still-valid persisted SVID and is the continuity control. The additive corrective reboot started with no cached SVID and directly recorded fresh `tpm_devid` attestation start and success after 33 seconds under the same host node SPIFFE ID with a new serial. All five host safety fields were green, and the guest chain was restored. C1-F1 records the broker's fail-closed relay dependency. C1-F2 records stale configured bootstrap trust after CA rotation | **PASS WITH FINDINGS; accepted. C1-F1 and C1-F2 are both preserved** | Both temporary entries and fetched SVID files removed; two nonces consumed; backups removed; temporary autostart reverted; relay restored; two chain entries retained | The two runs prove cached-SVID continuity and fresh post-boot `tpm_devid` separately. Fresh attestation necessarily used the TPM transiently. No operator-invoked TPM command ran, and no persistent TPM object was intentionally created, evicted, or written. Persistent TPM namespace equality was not re-inventoried; prior P3 evidence remains separate. Production needs durable broker SVID sourcing and rotation-aware atomic distribution of overlapping current and next bootstrap authorities with a mandatory pre-delete bundle validation gate | [`case-01-host-reboot.md`](./case-01-host-reboot.md) |
| 2 — Host agent restart | Node identity continuity; broker reconnects to the Broker UDS | The restarted agent loaded its persisted SVID with the same ID and serial without invoking the node attestor. The untouched broker reconnected to the recreated Broker UDS after the P9 relay was manually restored | **PASS on all six checkpoints** | Three nonces spent; staged payload shredded; bootstrap key clear; relay restored; no entry or instance changes | Supports host-agent restart continuity. The relay remains spike scaffolding that must be replaced by a durable production SVID source | [`case-02-host-agent-restart.md`](./case-02-host-agent-restart.md) |
| 3 — Guest restart | Match the P9 fresh-credential re-attestation story | Agent-process restart failed closed without the destroyed exchange keypair. Guest reboot preserved UUID and generation; a pre-reboot nonce remained valid; one full bootstrap restored the same node ID with new credentials | **PASS on all eight checkpoints** | Temporary entry deleted; fetched SVID files shredded; bootstrap key clear; guest A left healthy; no snapshot or clone remained | Supports fresh-credential-per-boot behavior. A plain reboot does not invalidate an outstanding generation-bound nonce | [`case-03-guest-restart.md`](./case-03-guest-restart.md) |
| 4 — Nonce replay | Reject reuse after redemption in the full chain | Initial redemption completed the full chain. Two replays returned `409`/`conflict` before another consume or Broker call and produced no credential | **PASS** | Staged nonce copy shredded; bootstrap key clear; exchange material shredded and unmounted; no entry changed | Confirms atomic single use and the replay portion of the fail-closed criterion. It does not mitigate theft before first use | [`case-04-nonce-replay.md`](./case-04-nonce-replay.md) |
| 5 — Wrong instance | B cannot read A’s nonce; B’s material cannot request A’s identity; separately measure theft of A’s unused bearer value | Q1: B could not see A’s value. Q2: B’s claimed A UUID was rejected and B’s own material resolved only B. Q3: a deliberately transferred, unused A value redeemed from B and returned an A exchange credential. `[INFERENCE from observed P8 and P9 contracts]` That credential can complete `x509pop` as A | **FINDING; case acceptance met. Q1 PASS, Q2 PASS, Q3 required finding confirmed** | Seventeen scratch files shredded; tmpfs unmounted; both bootstrap keys clear; entries and nodes unchanged | High residual risk: unused bearer values are portable. Caller binding is required to eliminate that portability and is not implemented; P11 must evaluate mitigation or explicit risk acceptance | [`case-05-wrong-instance.md`](./case-05-wrong-instance.md) |
| 6 — Clone | Copy receives the P6 UUID/selector outcome and cannot assume A’s identity | `incus copy` generated a new UUID and generation. Copied public state lacked the private key and exchange material. Clone redemption bound to the clone UUID and returned no SVID; A’s node was unchanged. `[INFERENCE]` Selector mismatch caused the empty result because no host-agent selector transcript was available | **PASS** | Clone and source snapshot deleted; clone nonce burned; original guests, entries, and nodes unchanged | Supports the `incus copy` path: copy re-keys both anchors and copied public state is unusable. It does not establish import safety | [`case-06-clone.md`](./case-06-clone.md) |
| 7 — Snapshot restore | Generation change invalidates old state; restored guest re-bootstraps; stale SVID expires without renewal | Restore preserved UUID and changed generation. The old-generation nonce was consumed and rejected; the old workload SVID expired with no renewal path; fresh bootstrap restored the same node ID with new credentials. C7-F1 records generic external `409` with the precise mismatch retained in the journal | **PASS, with informational state-machine behavior C7-F1** | Two temporary entries, snapshot, staged payloads, and rendered configs removed; both guests and chain state healthy | Supports fail-closed restore behavior. Production restore procedure must require fresh bootstrap and preserve nonce-ID-correlated generation-mismatch logs | [`case-07-snapshot-restore.md`](./case-07-snapshot-restore.md) |
| 8 — Migration | Defer real member migration on this single node; run project-move and stopped export/import proxies | Real member migration was unavailable. Proxy A preserved UUID and generation across a project move while changing project and `created_at`. Proxy B replayed UUID, generation, and `created_at` on import and allowed concurrent duplicate anchors after MAC deduplication | **DEFERRED for real cluster-member migration; both required proxies completed** | Imported and original proxy instances, both projects, and export tarball removed; proxy UUID resolved nowhere; no snapshot remained | Real migration alone remains conditional. Import replay is a separate high-severity architecture decision input, P10-ARCH-001, and is not covered by the migration deferral | [`case-08-migration.md`](./case-08-migration.md) |
| 9 — Delete and recreate | New UUID; old entry and nonce do not apply; no name-based confusion | Same-name recreation produced new UUID and generation. Old UUID matched no instance; the old in-TTL nonce returned `409` with internal `instance not found`; mint-by-name fields were rejected; fresh material derived only the new UUID | **PASS** | Two throwaway entries, recreated instance, and scratch files removed; old bootstrap key died with the original instance. `[INFERENCE]` Disposal of the specific old nonce by the reaper was not directly observed | Supports UUID anchoring and rejection of name as an input anchor | [`case-09-delete-recreate.md`](./case-09-delete-recreate.md) |
| 10 — Stale credentials | Expired nonce, expired exchange SVID, and deleted entry each fail cleanly with recorded errors | Expired nonce returned `409`; expired exchange SVID failed `x509pop` with `PermissionDenied`; deleted entry produced `503`/`nonce_consumed_without_svid`. No stale state produced an identity; fresh bootstrap recovered | **PASS** | Expired nonce reaped; retained exchange material shredded and tmpfs unmounted; exchange entry recreated with the same identity shape; guest A restored healthy with fresh credentials | Supports machine-readable fail-closed stale-state handling. The deleted-entry path burns an in-flight nonce and requires a fresh mint | [`case-10-stale-credentials.md`](./case-10-stale-credentials.md) |

## Acceptance result

The completed-case verdict accounting matches the P10 acceptance result recorded by the source fragments:

- Cases **2–4, 6–7, and 9–10** carry PASS verdicts. Case 1 is **PASS WITH FINDINGS and accepted** after the additive corrective reboot directly closed the fresh-`tpm_devid` gap. Case 7 retains its qualification.
- Case 5 is **FINDING, with case acceptance met**: Q1 passes, Q2 passes, and Q3 confirms the explicitly required bearer-token finding. It is not a generic failure.
- Case 8 remains **DEFERRED** only for real cluster-member migration. Both required proxies ran: stopped cross-project move and stopped export/import. The deferral is not a generic failure and does not defer the separate import-replay finding.
- Every case completed its local cleanup. Per the live Teardown Inventory in Appendix E, both guests and their guest-chain infrastructure remain intentionally live for P11's ordered teardown; this is the P10 handoff state, not an incomplete P10 action.

### Independent wave 3 and corrective review

- **Case 2: ACCEPTED.** The same host node ID and serial persisted, and the untouched broker process reconnected to the recreated Broker UDS. Manual relay restoration supplied the broker's own SVID; it was not needed to reconnect the UDS.
- **Case 3: ACCEPTED.** The process restart failed closed, the plain reboot preserved UUID and generation, the unused pre-reboot nonce redeemed, and fresh credentials restored the same node ID and Workload API.
- **Case 1: ACCEPTED, PASS WITH FINDINGS.** The original reboot remains the persisted-SVID continuity control. The additive corrective reboot directly recorded no cached SVID, node-attestation start and success after 33 seconds, the same host SPIFFE ID with a new serial, five green host safety fields, and restoration of the guest chain.
- **C1-F1: MEDIUM availability and boot-recovery requirement.** The relay binary is spike scaffolding, but production needs durable broker SVID sourcing plus supervised boot ordering and readiness. The broker otherwise fails closed without a listener.
- **C1-F2: MEDIUM bootstrap-trust availability requirement.** Configured bootstrap trust can become stale after CA rotation. Deleting persisted agent state then fails closed and drops dependent identity services until bootstrap trust is refreshed. No bypass or impersonation occurred.
- P10-ARCH-001 is unaffected and remains a separate P11 decision input.

## Findings and current effect

| Finding | Severity | Direct observation | Current effect |
|---|---|---|---|
| C1-F1 — broker boot depends on the manually restored P9 relay | **Medium availability and boot-recovery requirement** | The broker service was active after boot but did not bind `:8443` for 78 seconds. Restoring the relay unblocked it nine seconds later without a broker restart | Fail-closed availability dependency, not an identity bypass. Production needs a durable Workload API source, supervised boot ordering, and readiness rather than the manually restored spike relay |
| C1-F2 — configured bootstrap trust became stale after CA rotation | **Medium bootstrap-trust availability requirement** | After the operator removed only `agent-data.json`, `keys.json` was initially unchanged and SPIRE's disk KeyManager later rewrote it while generating a new keypair. The agent could not open the attestation stream because the configured bootstrap bundle lacked the current authority; the broker stayed down. Recovery used authoritative `spire-server bundle show` over the authenticated Incus administrative channel | Fails closed; no bypass or impersonation occurred. Production mitigation is rotation-aware atomic distribution of overlapping current and next authorities plus a mandatory pre-delete bundle validation gate |
| Unused bearer value is portable | **High residual risk** | B could not read or claim A through its own boundaries, but a deliberately transferred unused A value redeemed from B and returned an A exchange credential | Instance boundaries and server-side UUID resolution do not bind the redeemer. Caller binding remains unimplemented; P11 must evaluate a binding or explicit risk acceptance |
| C7-F1 — old-generation nonce is spent on generation mismatch | **Informational** | First submission returned generic `409` and logged the precise generation mismatch; replay returned `409` and logged already used | Fails closed and has no current go/no-go effect. Operators need durable nonce-ID-correlated logs |
| P10-ARCH-001 — supported import replays authoritative anchors | **High for the architecture decision** | Export/import replayed UUID, generation, and `created_at`; two instances then ran concurrently with the same anchors. Multi-match rejection prevents silent selection | Current adoption has a blocking NO-GO input until import re-keys or rejects duplicates, or authoritative global uniqueness plus lifecycle reconciliation is proven. This is a P11 input, not the final P11 decision |
| Deleted-entry redemption burns the in-flight nonce | **Informational** | With the entry absent, redemption returned `503`/`nonce_consumed_without_svid`, issued no identity, and cleared the bootstrap key | Known fail-closed lifecycle rough edge; recovery requires a fresh mint |

P10-ARCH-001 has two defensible severity views. On the single node observed, the multi-match hard failure limits the immediate outcome to issuance unavailability, which can be classified as a **medium availability-control failure**. For the architecture decision, the same supported lifecycle operation contradicts the assumption that UUID and generation form a unique authoritative anchor. The matrix therefore uses **High**: the duplicate is reachable without anchor tampering, affects the identity model rather than only one request, and has no proven re-key, rejection, global-uniqueness, or reconciliation control. This severity choice does not make P11’s final adoption decision.

## Case details

### Case 1 — Host reboot

- **Expected:** The host agent re-attests via `tpm_devid`, guests recover per the P9 story, and the TPM-unlock invariant is re-verified.
- **Observed:** The original reboot loaded a still-valid persisted SVID and remains the continuity control. The additive corrective reboot started without a cached SVID and directly recorded node-attestation start and success after 33 seconds under the same host node SPIFFE ID with a new serial. The five host safety fields were green, and the guest chain was restored. Fresh `tpm_devid` necessarily accessed the TPM transiently. No operator-invoked TPM command ran, and no persistent TPM object was intentionally created, evicted, or written. Persistent TPM namespace equality was not directly re-inventoried in the corrective rerun; prior P3 evidence remains separate.
- **Verdict:** **PASS WITH FINDINGS; accepted.** C1-F1 is the Medium fail-closed broker relay dependency. C1-F2 is the Medium stale-bootstrap-trust availability finding; no bypass or impersonation occurred.
- **Cleanup:** Both temporary entries, fetched SVID material, backups, and temporary autostart were removed; two nonces were consumed. The relay was restored and the intended spike chain remained live. Case-local cleanup passed. Both guests and their live guest-chain infrastructure intentionally pass to P11 for Appendix E's ordered teardown; no P11 decision is claimed.
- **Architecture effect:** Production needs durable broker SVID sourcing with supervised boot ordering and readiness. Bootstrap trust requires rotation-aware atomic distribution of overlapping current and next authorities plus a mandatory pre-delete validation gate. Corrective recovery sourced the authoritative bundle from `spire-server bundle show` over the authenticated Incus administrative channel.
- **Source:** [`case-01-host-reboot.md`](./case-01-host-reboot.md).

### Case 2 — Host agent restart

- **Expected:** Stable node identity and broker reconnection to the Broker UDS.
- **Observed:** The agent loaded its persisted SVID without invoking the node attestor. After manual relay restoration, the broker reconnected to the new UDS without restarting.
- **Verdict:** **PASS on all six checkpoints.** The P9 relay, not the broker connection, was the restart casualty.
- **Cleanup:** All three nonces were spent, the staged payload was shredded, and the relay was restored. No registration entry or instance changed.
- **Architecture effect:** Supports restart continuity while preserving the relay-scaffolding qualification.
- **Source:** [`case-02-host-agent-restart.md`](./case-02-host-agent-restart.md).

### Case 3 — Guest restart

- **Expected:** The P9 fresh-credential re-attestation story.
- **Observed:** Process restart failed closed without the exchange keypair. Reboot preserved UUID and generation, so the pre-reboot nonce remained usable; fresh credentials restored the same node ID.
- **Verdict:** **PASS on all eight checkpoints.** The case did not exercise an in-flight re-attestation of an already running agent.
- **Cleanup:** Temporary workload entry and fetched material were removed, the bootstrap key was clear, and guest A remained healthy.
- **Architecture effect:** Confirms fresh credential bootstrap after reboot, but also shows that reboot alone does not invalidate a generation-bound unused nonce.
- **Source:** [`case-03-guest-restart.md`](./case-03-guest-restart.md).

### Case 4 — Nonce replay

- **Expected:** A consumed nonce is rejected inside the full chain.
- **Observed:** Both replays returned `409`/`conflict` without another consume or Broker call and without credential material.
- **Verdict:** **PASS.** This is consumed-nonce replay evidence, not exchange-certificate replay evidence.
- **Cleanup:** The staged copy and exchange material were removed; no registration entry changed.
- **Architecture effect:** Supports single-use replay protection but does not address theft before first use.
- **Source:** [`case-04-nonce-replay.md`](./case-04-nonce-replay.md).

### Case 5 — Wrong instance

- **Expected:** Q1 and Q2 enforce instance boundaries; Q3 records whether a stolen, unused value is portable.
- **Observed:** Q1 **PASS** — B could not read A’s value. Q2 **PASS** — B could not claim A with B’s material. Q3 **required finding confirmed** — possession of A’s unused value was sufficient to obtain A’s exchange credential from B. The further statement that B could become A’s node is explicitly an inference composed from the prior P8 and P9 live contracts.
- **Verdict:** **FINDING; case acceptance met.** The portable bearer result is required evidence, not a generic case failure.
- **Cleanup:** Scratch files were shredded, tmpfs was unmounted, bootstrap keys were clear, and entries and nodes were unchanged.
- **Architecture effect:** Caller binding is required to eliminate portability and is currently unimplemented. The documented controls limit exposure but do not identify the caller.
- **Source:** [`case-05-wrong-instance.md`](./case-05-wrong-instance.md).

### Case 6 — Clone

- **Expected:** The clone receives fresh anchors and cannot assume A’s identity.
- **Observed:** Copy generated a fresh UUID and generation. The copied disk held no usable SPIRE key or exchange material; clone-bound redemption returned no SVID; A remained unchanged. The selector-mismatch cause is an inference because the host-agent selector transcript was unavailable.
- **Verdict:** **PASS.** This verdict applies to `incus copy`, not export/import.
- **Cleanup:** The clone and source snapshot were deleted and the clone nonce was dead.
- **Architecture effect:** Supports copy re-keying as the safe duplication behavior and establishes the contrast with case 8 import replay.
- **Source:** [`case-06-clone.md`](./case-06-clone.md).

### Case 7 — Snapshot restore

- **Expected:** New generation invalidates old state; fresh bootstrap restores the stable UUID-derived node ID.
- **Observed:** UUID stayed stable, generation changed, the stale nonce failed closed, the stale workload SVID expired without renewal, and fresh bootstrap restored the same node ID with new credentials.
- **Verdict:** **PASS, with informational C7-F1.** The stale nonce is spent on generation mismatch; the caller sees generic `409`, while the durable journal retains the precise cause.
- **Cleanup:** Both temporary entries, the snapshot, staged payloads, and temporary configs were removed.
- **Architecture effect:** Supports generation-based rollback discrimination and requires fresh-bootstrap restore procedures plus durable correlated logs.
- **Source:** [`case-07-snapshot-restore.md`](./case-07-snapshot-restore.md).

### Case 8 — Migration

- **Expected:** Defer real cross-member migration and run both single-node proxies.
- **Observed:** The host was not clustered. Project move preserved UUID and generation while changing project and `created_at`. Export/import replayed UUID, generation, and `created_at` and permitted concurrent duplicate anchors after MAC deduplication.
- **Verdict:** **DEFERRED for real cluster-member migration; both proxies completed.** P10-ARCH-001 is an independently observed import result, not a deferred claim.
- **Cleanup:** Both proxy instances and projects and the export tarball were removed; the proxy UUID had no remaining match.
- **Architecture effect:** Real migration must still prove cross-member anchor and lookup behavior. Import requires re-key/reject or proven global uniqueness and reconciliation before the anchor model satisfies the added GO condition.
- **Source:** [`case-08-migration.md`](./case-08-migration.md).

### Case 9 — Delete and recreate

- **Expected:** Same-name recreation gets a new UUID; old entries and nonces cannot transfer by name.
- **Observed:** UUID and generation changed; the old UUID had zero matches; the old nonce failed on the dead UUID; name fields were not accepted as lookup inputs.
- **Verdict:** **PASS.** The new instance derived only its new UUID-based identity.
- **Cleanup:** Both throwaway entries, the recreated instance, and scratch files were removed. The old nonce was unusable; its specific reaper disposal was not directly observed.
- **Architecture effect:** Supports UUID as the anchor and name only as derived informational context.
- **Source:** [`case-09-delete-recreate.md`](./case-09-delete-recreate.md).

### Case 10 — Stale credentials

- **Expected:** Each stale state fails cleanly with a recorded error.
- **Observed:** Expired nonce, expired exchange SVID, and deleted entry each failed with distinct machine-readable results and issued no identity. Fresh bootstrap recovered the chain.
- **Verdict:** **PASS.** Deleted-entry redemption retains the known in-flight nonce-burn behavior.
- **Cleanup:** The reaper withdrew the expired nonce, retained exchange material was removed, the entry was recreated with the same identity shape, and guest A was restored healthy.
- **Architecture effect:** Supports fail-closed stale-state behavior; operational recovery from an in-flight burn requires a new nonce.
- **Source:** [`case-10-stale-credentials.md`](./case-10-stale-credentials.md).

## Closing live state

The final wave record directly observed the host safety fields green; two attested nodes; two registration entries; the broker active at digest `4ed87f92ca113334c2e2e60127ae00131a47273ac476dd1d2f05b8f2e463fa45`; the relay restored; both guests running; both bootstrap keys clear; and guest A healthy. This is the retained P10 spike state, not P11 teardown or a final adoption decision.

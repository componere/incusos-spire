# P8 architectural security findings

**Status:** go/no-go input for the post-spike architecture

This document records the independent P8 security review and the design consequences of the live P8 run. It does not treat architecture findings as code defects to patch during the spike. Code line references are to the reviewed tree at commit `5a9bee7`.

The review IDs below follow `/tmp/p8-security-review.md`. Candidate mitigations have not been implemented or tested unless stated otherwise; they are marked `[ASSUMPTION]`.

## Summary

| Finding | Severity | One-line statement | Disposition |
|---|---|---|---|
| **SEC-009** | **High** | The `spike-attestor-ro` reader can retrieve the full config of every project instance, including an outstanding `user.spiffe-bootstrap` secret. | **Architecture decision.** Do not patch around this in the spike; decide whether to replace or redesign the carrier before production. |
| **SEC-001** | **High** | The network-facing broker loads both the trusted reader and the project-wide instance mutation credential. | **Architecture decision.** Separate the credential-bearing processes before production. |
| **SEC-002** | **High** | The operator mint endpoint has no authentication or application capacity bound. | **Fix in spike code.** Authenticate and bound the operator path; prune nonce records. |
| **SEC-004** | Medium | A cancelled mint can leave a live issuance after Incus applied the config write but before the caller received success. | **Fix in spike code.** Use independent bounded compensation and reconcile ambiguous writes. |
| **SEC-006** | Medium | The lifecycle matrix can report a security pass after a dependency or transport failure. | **Fix in spike harness.** Require the exact security outcome and fail on dependency failures. |
| **SEC-007** | Medium | Harness cleanup suppresses failures and can report cleared state while secret-bearing config or files remain. | **Fix in spike harness.** Verify cleanup and make any residue fail the run. |
| **SEC-003** | Low | A known nonce ID is distinguishable from an unknown ID before secret verification through timing and backend-dependent status. | **Architecture/production hardening decision.** Do not patch in this spike; define a uniform pre-verification path. |
| **SEC-005** | Low | Clearing Go string fields and shell variables does not erase the request material from memory or prior buffers. | **Architecture/operational decision.** Do not claim memory erasure; minimize copies and define process-memory controls. |
| **SEC-008** | Low | The documented per-mint `ttl_seconds` was silently ignored and the process-wide TTL applied instead. | **Fix in spike code.** Validate and apply a bounded per-mint TTL or reject the field. |

Evidence anchors for the code-hardening findings:

- SEC-002: `cmd/incus-spiffe-broker/service.go:271-326` performs mint without an authorization check; `cmd/incus-spiffe-broker/main.go:324-334` configures server TLS without client authentication; `internal/nonce/memory/store.go:23-52` creates and adds to an in-memory map without pruning.
- SEC-004: `internal/nonce/lifecycle.go:272-290,359-367` compensates through the caller context; `internal/nonce/memory/store.go:113-128` refuses deletion after context cancellation.
- SEC-006 and SEC-007: `spike/p8/lifecycle-matrix.sh:181-190,385-395,540-548,594-602,624-689,743-778` contains the non-strict verdict and best-effort cleanup paths found by the review. The live run used `STRICT_STATUS=1`, but case (e) still aborted when the stock guest lacked `jq`; see [`matrix-run1-abdefghi.txt`](./matrix-run1-abdefghi.txt) and [`case-e-deleted-instance.txt`](./case-e-deleted-instance.txt).
- SEC-003: `cmd/incus-spiffe-broker/service.go:359-377` performs the live Incus lookup before `Minter.Redeem` checks the secret; `cmd/incus-spiffe-broker/service.go:549-573` maps the resulting failures to different status classes.
- SEC-005: `cmd/incus-spiffe-broker/service.go:341-350,518-526` decodes into ordinary Go strings and buffers; `internal/nonce/nonce.go:48-64,93-112` stores the secret in an immutable string and converts it again for hashing.
- SEC-008: `cmd/incus-spiffe-broker/service.go:98-105,518-526` omits `ttl_seconds` and accepts unknown fields. The live workaround is recorded in [`case-c-expiry.txt`](./case-c-expiry.txt).

Live finding F2 is related but is not one of the review's nine numbered findings: the expired value remained readable from the guest socket in [`case-c-expiry.txt`](./case-c-expiry.txt). The spike code hardening therefore also needs a reaper that clears unredeemed expired keys.

## SEC-009 — the secret-carrier gap

**Severity: High. Architecture go/no-go input.**

The P8 design places the nonce secret in the JSON written to `user.spiffe-bootstrap` (`internal/nonce/lifecycle.go:276-290`). The design and code comments then treat the instance config key as if it were a guest-only destination (`cmd/incus-spiffe-broker/service.go:107-113` and `cmd/incus-spiffe-broker/doc.go:58-64`).

P5 disproved that premise for the management plane:

- Incus 7.3 returned the full instance `config` map when `server:incus can_view_sensitive` was denied ([P5 evidence](../p5/EVIDENCE.md), line 211).
- `spike-attestor-ro` can read the full record of every instance in `spike-spiffe` ([P5 evidence](../p5/EVIDENCE.md), lines 301-303).
- The authorization scriptlet decides on an object and entitlement. It does not receive a config-key selector or the request body, so Incus cannot authorize a read of `volatile.*` while hiding only `user.spiffe-bootstrap` ([P5 evidence](../p5/EVIDENCE.md), lines 124-133 and 211).
- The SPIRE attestor plugin loads this reader credential inside the attestation trust boundary (`cmd/incus-attestor/doc.go:1-10,26-31`). The broker at the reviewed commit also loads it (`cmd/incus-spiffe-broker/main.go:253-264`).

Therefore, any holder of `spike-attestor-ro` can retrieve an outstanding bootstrap payload through the Incus management API. If that holder redeems first, the legitimate guest loses the single-use race. This **falsifies the implicit claim that only the guest receives the secret**. P8 proved that guest B cannot read A's key through B's own `/dev/incus/sock`; it did not prove that the management-plane reader cannot read the same key.

The read capability was proved live in P5. The complete theft path with `spike-attestor-ro` was not executed in P8. `[ASSUMPTION]` A holder that reads and submits the still-unused value before the guest will receive the bound identity because the live bearer-token test proved that possession, not caller location, controls redemption.

### Candidate mitigations

| Candidate | Tradeoff | Independent-attestation verdict |
|---|---|---|
| **(a) Carry only a nonce ID and no secret.** Require the guest to prove possession of some other instance-bound material. | `[ASSUMPTION]` This removes the reader-visible bearer secret, but the nonce ID alone authenticates nothing. A new proof protocol and a source of guest-only material are required. | **Conditional yes.** It preserves independent attestation only if the other proof is bound to the guest and the attestor still derives identity from Incus rather than trusting a guest claim. |
| **(b) Carry a value useless to a reader.** Examples are a hash whose preimage arrives through a separate authenticated path, or ciphertext encrypted to a guest-held key delivered out of band. | `[ASSUMPTION]` A hash by itself does not give the guest a proof; the preimage must come from somewhere the reader cannot access. Encryption adds guest key generation, key delivery, rotation, and replacement requirements. | **Hash alone: no. Encrypted value: conditional yes.** Encryption preserves the property only if the private key is already guest-held and cannot be replayed or read through the management plane. |
| **(c) Replace the carrier.** Candidate side channels are cloud-init vendor data or vsock, which the P8 failure-interpretation clause already names (`SPIKE_PLAN.md:229`; §10 at lines 309-311). | `[ASSUMPTION]` Each channel needs a new experiment proving per-instance delivery, live-update behavior, access control, and that `spike-attestor-ro` cannot retrieve the carried secret through another API representation. | **Conditional yes.** A carrier can preserve independent attestation if delivery is instance-bound and the credential that reads authoritative identity cannot read or inject the proof. |
| **(d) Accept the exposure and shorten it.** Use a TTL measured in seconds and a reaper that clears expired, unredeemed keys. | `[ASSUMPTION]` This reduces the race window and residue. It increases sensitivity to clock, boot, and service latency and does not stop a reader that acts within the window. The live run proved the key remains readable after expiry without a reaper ([`case-c-expiry.txt`](./case-c-expiry.txt)). | **No.** This limits exposure but does not preserve the claim that only the guest can present the proof. |

No choice should be described as a per-key Incus authorization fix. P5 already proved that Incus 7.3 does not expose that policy granularity.

## SEC-001 — credential co-location

**Severity: High. Architecture go/no-go input.**

The reviewed network service creates both adapters in one process before opening its TLS listener:

- `cmd/incus-spiffe-broker/main.go:253-264` loads the `spike-attestor-ro` certificate and private key.
- `cmd/incus-spiffe-broker/main.go:266-277` loads the `spike-bootstrap-writer` certificate and private key.
- `cmd/incus-spiffe-broker/main.go:289-306` composes both into the service.

This contradicts the documented boundary that describes the network service as holding the writer while the SPIRE plugin holds the reader (`cmd/incus-spiffe-broker/doc.go:15-31`). It also conflicts with P6 rule 4: no principal that can write instance config may be inside the attestation trust boundary ([P6 reference schema](../p6/REFERENCE_SCHEMA.md), lines 58-65).

P5 measured the writer's raw residual powers. The smallest Incus 7.3 grant can write every config key, including `volatile.uuid` and `volatile.uuid.generation`, and can delete or rename any instance in `spike-spiffe` ([P5 evidence](../p5/EVIDENCE.md), lines 304-319). The Go adapter's key allowlist does not constrain an attacker that has the private key.

**Blast radius.** A memory disclosure or code-execution compromise of the network-facing broker exposes the reader that the attestation path trusts and the writer that can forge the identity anchors it reads. The same compromise can also mutate arbitrary instance config, delete instances, and authorize renames across the project. `[ASSUMPTION]` No broker compromise was executed during P8; the impact follows from the observed credential powers and their code-level co-location.

### Required separation

| Option | Boundary | Tradeoff |
|---|---|---|
| **Separate mint and redeem processes.** | `[ASSUMPTION]` The guest-facing redeem listener holds the reader but never the writer. An authenticated operator-side mint process holds the writer and is not exposed on the guest network. | This narrows the guest-listener blast radius, but the mint process may still need authoritative UUID-to-name resolution. If it loads the reader as well, co-location remains in that process; use the narrow helper below or a trusted provisioning path to eliminate it. The processes also need authenticated IPC and coordinated nonce lifecycle state. |
| **Put the raw writer behind a narrow local service.** | `[ASSUMPTION]` A non-networked helper holds only the writer and exposes exact set/clear operations for `user.spiffe-bootstrap`. The network listener cannot read the key file or send raw Incus requests. | A compromised listener could still invoke allowed set/clear operations, so the helper must validate the project, key, payload shape, instance target, and operation. This removes access to the writer's unrelated raw powers but adds a local authorization and deployment boundary. |

The minimum production rule is direct: **the network listener must never possess the raw writer credential**. This separation reduces SEC-001. It does not close SEC-009; the reader-visible secret carrier must be decided separately.

## Operational semantics required before production

The following live findings are not cosmetic error-message differences. Each changes retry, fleet diagnosis, or restart behavior.

| Finding | Observed behavior | What production must add | Evidence |
|---|---|---|---|
| **F3 — rejection burn semantics are inconsistent and invisible.** | A generation change consumed the nonce; the next identical attempt reported already used. An instance-not-found failure occurs before consumption. Both caller responses were HTTP `409` with the same conflict body. | Define one terminal retry contract and one deliberate burn point. Until that exists, P9 and every later client must treat **every `409` as terminal**, discard the payload, and request a fresh issuance. Production also needs internal reason metrics that distinguish lifecycle causes without exposing nonce state to the caller. | [`supplementary-burn-semantics.txt`](./supplementary-burn-semantics.txt), especially the two attempts and broker reasons; [`case-e-deleted-instance.txt`](./case-e-deleted-instance.txt); code order at `cmd/incus-spiffe-broker/service.go:359-380` and `internal/nonce/lifecycle.go:323-340`. |
| **F4 — deletion and lost read grant are indistinguishable.** | The deleted-instance case returned `attestor: instance not found`. P7 had already shown that a trusted but under-privileged reader can produce the same empty/not-found result. A fleet-wide credential failure can therefore look like mass instance deletion. | Add a typed adapter distinction between authoritative zero matches, authorization/grant failure, and backend failure. Keep the external denial as uniform as needed, but expose separate health checks, metrics, and operator alerts so fleet authorization loss is diagnosed as a credential incident. | [`case-e-deleted-instance.txt`](./case-e-deleted-instance.txt); [P8 evidence](./EVIDENCE.md), lines 390-395; P5's filtered-empty authorization behavior at [P5 evidence](../p5/EVIDENCE.md), lines 219-245. |
| **F5 — restart erases nonce state.** | The only composed store is `memory.New()` (`cmd/incus-spiffe-broker/main.go:289`). A restart loses all outstanding records while the config payload remains. The guest then receives the same HTTP `401` used for a forged or unknown nonce ID (`cmd/incus-spiffe-broker/service.go:549-553`). | Add a durable atomic store with restart restoration and reconciliation of instance keys, or define an explicit restart procedure that invalidates, clears, and remints every outstanding issuance. Production monitoring must distinguish a restart-driven wave of invalidations from an attack without changing the caller's confidentiality-preserving response. | [`case-c-expiry.txt`](./case-c-expiry.txt) records the service restart used by the live expiry test; [P8 evidence](./EVIDENCE.md), lines 397-403. |

## Bearer-token risk

The plan required this measurement rather than an expected rejection. P8 step 5 says that a deliberately leaked, unused A nonce is a bearer credential and may impersonate A; the acceptance criterion makes that result an explicit go/no-go input (`SPIKE_PLAN.md:226-228`). Risk R10 repeats the same expectation (`SPIKE_PLAN.md:328`).

The live result matched it exactly. Guest A read an unused payload, the harness transferred it to guest B, and B redeemed it. The broker returned HTTP `200`, A's instance identity, and all six frozen `incus:` selectors. See [`matrix-run1-abdefghi.txt`](./matrix-run1-abdefghi.txt), case (i), and [P8 evidence](./EVIDENCE.md), lines 322-360.

This is not closed by server-side UUID lookup, single use, a short TTL, per-instance guest-socket visibility, or a reaper. Those controls constrain normal delivery and the exposure window. They do not distinguish the intended guest from another caller that possesses the unused value.

`[ASSUMPTION]` The mitigation direction that closes the bearer property is to bind redemption to something the guest can prove and an attacker who copied the nonce cannot replay—for example, proof of possession of a guest-held private key whose public key reaches the verifier through an independently authenticated path. The key and delivery mechanism remain unbuilt and require a new experiment. Accepting a shorter bearer window is risk acceptance, not closure.

## What P8 genuinely proved

### Supported by code and the live run

| Supported claim | Evidence and limit |
|---|---|
| The positive mint/read/redeem path works and returns the six frozen selectors for the bound instance. | [`positive-01-mint.txt`](./positive-01-mint.txt) through [`positive-04-key-cleared.txt`](./positive-04-key-cleared.txt). This proves the P8 metadata response, not the P9 exchange SVID or guest-agent bootstrap. |
| In one broker process, concurrent redemption is atomic: two successes did not occur. | [`case-d-strict-concurrency.txt`](./case-d-strict-concurrency.txt) recorded three close races, each `200/409`; `internal/nonce/memory/store.go:55-93` holds the compare, expiry check, used check, and commit under one mutex. This does not prove cross-process atomicity for a future distributed store. |
| Expiry is enforced inclusively under the configured process TTL. | [`case-c-expiry.txt`](./case-c-expiry.txt) recorded HTTP `409` after a five-second process TTL. It also proved that expiry did not clear the key. The advertised per-mint TTL was not part of this proof. |
| Deletion and generation change fail closed. | [`case-e-deleted-instance.txt`](./case-e-deleted-instance.txt), [`matrix-run1-abdefghi.txt`](./matrix-run1-abdefghi.txt), and [`supplementary-burn-semantics.txt`](./supplementary-burn-semantics.txt). The two cases have different burn semantics, as F3 records. |
| Guest B cannot read A's key through B's own guest socket, and B's own nonce plus a claimed A UUID resolves to B. | [`matrix-run1-abdefghi.txt`](./matrix-run1-abdefghi.txt), cases (g) and (h). This proves guest-socket isolation and rejection of caller-asserted identity; it does not prove management-plane reader isolation. |
| An unused copied nonce is sufficient to obtain the bound identity. | [`matrix-run1-abdefghi.txt`](./matrix-run1-abdefghi.txt), case (i): B received A's identity, HTTP `200`, with all six selectors. |
| The successful redemption path consumes before clearing the config key. | Code order at `internal/nonce/lifecycle.go:323-340` and `cmd/incus-spiffe-broker/service.go:373-382`; the strict concurrency transcript observed the loser before the winner's clear log. A failed or abandoned redemption can still leave residue. |
| The reviewed implementation generates a 256-bit secret and a 128-bit public ID, stores only the secret hash, and uses constant-time digest comparison. | `internal/nonce/lifecycle.go:253-270,386-395`, `internal/nonce/memory/store.go:55-93`, and the independent review's code assessment. The live run did not measure entropy quality. |
| The Go writer adapter restricts its own methods to the bootstrap key, and the guest verifies the broker fingerprint before sending the request. | Code and current tests support the adapter allowlist; the live transcripts show the TLS fingerprint check before redemption. The raw writer credential remains broader than the adapter. |
| No nonce value appeared in the captured P8 logs or evidence. | [`secret-scan.txt`](./secret-scan.txt) records the executed scan and positive control. This is evidence-file and log redaction, not proof that process memory was erased. |

### False, partial, or only asserted

| Claim | Assessment |
|---|---|
| **“Only the guest receives the secret.”** | **False.** SEC-009 shows that the attestor reader can retrieve full instance config, including the carrier. |
| **The guest is securely and uniquely bound against every principal in the attestation trust boundary.** | **Only partial.** The guest socket is per-instance and caller claims are ignored, but the reader credential inside that boundary can read the bearer value. The broad H7 wording in [P8 evidence](./EVIDENCE.md), lines 40-44, is therefore too strong. |
| **Unknown-ID and wrong-secret failures are indistinguishable.** | **Partial.** The healthy response bodies match, but SEC-003 found different timing and backend-dependent outcomes because live resolution happens before secret verification. |
| **The dedicated state volume makes outstanding nonces restart-durable.** | **False.** The process constructs only `memory.New()`; the mounted volume does not hold nonce records. |
| **The caller can request a per-mint TTL.** | **False in the reviewed implementation.** The live test had to restart the broker with a different process TTL. SEC-008 is assigned to spike code hardening. |
| **The default lifecycle matrix proves each security decision rather than a dependency failure.** | **False in the reviewed harness.** SEC-006 identified fail-open verdicts. The live run enabled strict status checking, and case (e) still had to be repeated manually after its guest lacked `jq`. |
| **Cleanup always removes secret-bearing keys and files.** | **Asserted by the reviewed harness, not guaranteed.** SEC-007 found suppressed cleanup errors. The final live cleanup transcript proves the state of that run only. |
| **Secret request material is zeroed from memory.** | **False.** SEC-005 shows that ordinary Go strings, decoder buffers, shell variables, and prior file buffers are not erased by assigning an empty value. |
| **P8 proved the P9 credential exchange and durable guest identity.** | **Not tested.** P8 returned binding metadata and selectors only. P9 owns exchange-SVID delivery, guest-agent bootstrap, persistence, and the value of the credential that a stolen nonce would buy. |

The result is narrower than “H7 proven” but still useful: P8 proved the nonce mechanics, guest-socket isolation, server-side binding, and the exact bearer failure. It did not prove a guest-exclusive secret carrier or a production-safe trust boundary. Those two high findings are architecture decisions under the plan's contradiction protocol, not silent implementation substitutions.

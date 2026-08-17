# P9 architectural security findings

**Status:** go/no-go input for the post-spike architecture

This document records the independent P9 security review and the design consequences of the live P9 run. It does not treat the two high-severity architecture findings as code defects to patch during the spike. Code references are to the reviewed tree at commit `609885e`. Live references name P9 transcript files. Facts inherited from earlier phases name the phase that established them.

The review found eight defects. Six have a phase-local code or harness disposition. The two high findings remain architecture decisions under `SPIKE_PLAN.md:309-311`.

## Summary

| Finding | Severity | One-line statement | Disposition |
|---|---|---|---|
| **SEC-009 escalated** | **High** | The P8 bearer nonce now buys the bound instance's exchange X509-SVID chain, unencrypted PKCS#8 private key, and trust bundle, which is enough to become the derived guest node. | **Carried as an architecture decision.** The carrier and proof protocol require a production go/no-go decision. |
| **Broker blast radius** | **High** | One network-facing process holds both Incus credentials, access to the host agent's Broker socket, and a Workload API SVID authorized to request identities. | **Carried as an architecture decision.** Split the authorities and socket exposure before production. |
| **Redeem field contract mismatch** | Medium | The broker emits `exchange_cert_chain_pem`, `exchange_key_pem`, and `exchange_bundle_pem`, but the P9 harness did not accept those names without overrides. | **Fixed in the harness this phase.** The default extraction contract now matches the producer; the live mismatch remains recorded in `chain-02-field-name-mismatch.txt`. |
| **`x509pop` re-attestation versus shredding** | Medium | `x509pop` is re-attestable, but the spike removes the credential paths after initial attestation, so restart and eventual node re-attestation cannot use them. | **Carried as an architecture decision.** The harness now states the fresh-credential policy, but production must provision every re-attestation, not only each boot. |
| **Burned-nonce retry semantics** | Medium | A Broker failure after atomic consumption returns `500` or `503`, but retrying the same nonce can never succeed and creates a burn-based denial-of-service surface. | **Fixed in code this phase.** The response contract now treats post-consumption failure as terminal for that nonce; the production denial-of-service decision remains open. |
| **Overstated tmpfs and `shred` claims** | Medium | tmpfs can swap, and `shred` on tmpfs does not prove cryptographic erasure or that bytes never reached persistent media. | **Fixed in the harness this phase.** Claims are limited to no intentional persistent regular-file write and verified removal from the mounted tmpfs namespace. |
| **Root-only Workload API verification** | Medium | The live workload check ran as root against a `unix:uid:0` entry, so it did not prove that a non-root application can reach the guest Workload API. | **Fixed in the harness this phase.** A non-root check is required; the existing P9 transcript does not retroactively supply that live evidence. |
| **Incorrect response-delivery reporting** | Medium | The reviewed service logged `outcome=granted` before JSON delivery and ignored the returned write error, so a client disconnect could be recorded as successful delivery. | **Fixed in code this phase.** Success is recorded only after body delivery; delivery failure remains distinct from Broker issuance and nonce rejection. |

The field mismatch is visible at `cmd/incus-spiffe-broker/service.go:462-475` and `spike/p9/guest-agent-bootstrap.sh:682-700`; the failed live run is `chain-02-field-name-mismatch.txt`. The reviewed response-reporting order is at `cmd/incus-spiffe-broker/service.go:901-926`, with write errors produced at `cmd/incus-spiffe-broker/service.go:1116-1129`.

The current logging path redacts the key through `String`, `Format`, and `LogValue` (`cmd/incus-spiffe-broker/service.go:348-409,478-498`). This protection is not universal: `exchangeKeyPEM.MarshalJSON` deliberately reveals the key (`cmd/incus-spiffe-broker/service.go:373-382`). A future logger that JSON-marshals that value or an enclosing value without using the existing `LogValue` guard would disclose it. This is a documented limitation, not a key leak found in the reviewed execution path.

## SEC-009 escalated

**Severity: High. Architecture go/no-go input.**

### P8-to-P9 delta

| Phase | What a stolen, unused nonce buys | Evidence |
|---|---|---|
| **P8** | Binding metadata and the six selectors for the bound instance. P8 transferred an unused A payload to B; B redeemed it and received A's identity data. | P8 `matrix-run1-abdefghi.txt`, case (i); P8 `SECURITY_FINDINGS.md:97-105`. |
| **P9** | The same binding metadata and selectors, plus the bound instance's exchange X509-SVID chain, an unencrypted PKCS#8 private key, the trust bundle, and the exchange expiry. | Response contract at `cmd/incus-spiffe-broker/service.go:428-475`; exchange conversion at `cmd/incus-spiffe-broker/service.go:1268-1298`; successful chain in `chain-03-guest-bootstrap.txt`. |

P8 established that the nonce is a bearer credential and that a holder can win the single-use race. P9 established that a valid redemption returns an exchange credential and that this credential completes `x509pop` for the derived node identity, after which the guest Workload API can issue matching workload SVIDs (`chain-03-guest-bootstrap.txt`, `chain-04-agent-list.txt`, and `workload-02-fetch-and-rotation.txt`).

**[ASSUMPTION] Combining those two observed paths, a thief who redeems a copied, unused nonce first receives the bound instance's exchange credential, can complete `x509pop`, can become the derived guest node, and can obtain workload SVIDs registered beneath that node.** P9 did not repeat the deliberate stolen-nonce case end to end, but neither the response contract nor `x509pop` distinguishes the intended guest from another holder of the nonce and returned key. This remains a **High** finding.

The exchange TTL narrows exposure, but it is not a revocation control:

- It bounds the time available to start an `x509pop` attestation with that exchange certificate. The live P9 leaf was valid for about 130 seconds (`chain-03-guest-bootstrap.txt`).
- It does **not** make the exchange credential single-use. The nonce is single-use; the returned certificate and private key are not.
- It does **not** revoke a node SVID already issued through `x509pop`.
- It does **not** revoke workload SVIDs already issued beneath that node.

### Mitigation candidates and verdicts

These candidates are go/no-go inputs. Unless the table says otherwise, they were not implemented or tested.

| Candidate | P8/P9 basis | Verdict |
|---|---|---|
| **Keep the secret out of instance config entirely.** Carry only a public nonce ID there, or replace the carrier with a channel proved inaccessible to the management-plane reader. P8 named cloud-init vendor data and vsock as candidates. | P8 SEC-009 showed that Incus cannot authorize reads per config key. `SPIKE_PLAN.md:309-311` names an alternative guest side channel when H7 fails. | **[ASSUMPTION] Conditional closure.** The new channel must prove per-instance delivery, live update behavior, and that the attestor reader cannot retrieve or inject the proof. A nonce ID alone authenticates nothing. |
| **Carry a reader-useless value.** P8 proposed a hash whose preimage arrives through another authenticated path, or ciphertext encrypted to a guest-held key. | P8 `SECURITY_FINDINGS.md:51-60`. | **[ASSUMPTION] Conditional closure.** A hash alone is insufficient. Encryption helps only if the private key is already guest-held and the management plane cannot read or replay it. |
| **Use a CSR-style exchange.** The guest generates the keypair and sends only a public key or CSR; the broker returns a certificate chain and bundle. No exchange private key transits the broker or the instance config key. | P9 live analysis identifies this as the alternative worth pricing; `EVIDENCE.md:339-349`. The current Broker API instead returns the key in `internal/broker/client.go:102-115,348-356`. | **[ASSUMPTION] Exposure reduction, not SEC-009 closure by itself.** A stolen bearer nonce could submit the attacker's CSR unless redemption is also bound to guest-held proof. This requires an upstream Broker API or control-plane change. |
| **Bind redemption to something the guest can prove.** Require a non-replayable proof tied to guest-held material whose public part reaches the verifier through an independently authenticated path. | P8 bearer-token analysis, `SECURITY_FINDINGS.md:97-105`. P9 raises the value of the stolen credential. | **[ASSUMPTION] Conditional closure.** This closes the copied-nonce bearer property only if the copied nonce and management-plane read capability are insufficient to reproduce the proof. The attestor must continue to derive identity from authoritative Incus state rather than trust a guest identity claim. |
| **Shorten the nonce and exchange TTLs further and accept the residue.** P8 proposed a seconds-scale nonce TTL and reaper; P9 used a roughly two-minute exchange SVID and identified 30 seconds as a possible experiment. | P8 `SECURITY_FINDINGS.md:51-60`; P9 `EVIDENCE.md:339-349`. | **Risk acceptance, not closure.** A shorter TTL reduces the race and reuse windows, increases boot sensitivity, does not make the exchange credential single-use, and does not revoke issued node or workload SVIDs. |

## Broker blast radius

**Severity: High. Architecture go/no-go input.**

P8 recommended splitting the raw Incus credentials because the guest-facing process loads both adapters. P9 did not reduce that authority. It added an identity-issuance path to the same process:

| Authority in the broker | What compromise gives an attacker | Phase and evidence |
|---|---|---|
| **`spike-attestor-ro` Incus credential** | Read access to the full instance records in the project, including an outstanding bootstrap payload. This enables SEC-009's nonce theft path. | P5 measured the full-config read despite denial of `can_view_sensitive`; P8 SEC-009 recorded the consequence. The adapter is composed at `cmd/incus-spiffe-broker/main.go:429-439`. |
| **`spike-bootstrap-writer` Incus credential** | Raw authority beyond the Go allowlist: mutate arbitrary instance config, including identity anchors, and delete or rename project instances. | P5 measured the residual powers; P8 SEC-001 recorded them. The adapter is composed at `cmd/incus-spiffe-broker/main.go:442-453`. |
| **Host agent Broker socket** | A route to request exchange X509-SVIDs through the physically attested host agent for references that the server and host attestor accept. | P9 added the required socket at `cmd/incus-spiffe-broker/main.go:117-127,522-529`; the issued exchange SVID is recorded in `chain-03-guest-bootstrap.txt`. |
| **Broker's own Workload API SVID** | The mTLS client identity authorized by the host agent's Broker allow-list. Together with the Broker socket, it turns code execution in the network service into an identity-issuance path. | The Workload API source and mTLS connection are created at `internal/broker/client.go:117-193`; live authorization is in `deploy-04-config-and-startup.txt`. |

P9 also mounted the whole `spike-spire-agent-state` volume read-write into the broker to expose the two socket paths. The same volume holds the DevID certificate, CSR, and wrapped public/private TPM objects, plus Incus credential material (`deploy-02-socket-exposure.txt`). The TPM-resident private key is not contained in those blobs, so the mount does not by itself export the host identity key. It does expose the DevID artifacts and live socket endpoints to the guest-facing container.

**[ASSUMPTION] A broker compromise was not executed.** The impact follows from P5's observed Incus credential powers, P9's observed volume contents, and the composed P9 connection graph.

P9 makes the P8 split recommendation more urgent because the service now combines three classes of authority: authoritative Incus read, raw Incus mutation, and SPIFFE identity issuance. Production must, at minimum:

1. keep the raw writer credential out of the network listener, as P8 required;
2. isolate authoritative read from the guest-facing redemption surface or replace the reader-visible carrier;
3. expose only the two required socket paths, not the host agent state volume;
4. give the Broker client a narrowly scoped, independently attested identity source rather than the live run's shared-volume relay.

The P9 relay deliberately collapsed caller attestation to `unix:uid:0`; it was spike scaffolding, not a production boundary (`deploy-05-workload-api-relay.txt`).

## Exchange-key exposure inventory

The P9 exchange private key has no intentional persistent regular-file write. That narrow statement is supported by the code path and the live filesystem checks. It is not equivalent to “the key never reaches persistent media” or “the key is erased.”

**[ASSUMPTION]** Except for the observed tmpfs files, the process-memory locations below are inferred from the required data flow and reviewed code. P9 did not take process-memory dumps.

| Plaintext location | Why the key is there | Lifetime or limit |
|---|---|---|
| **Host agent Broker response and protobuf buffers** | The host agent mints and returns the complete X509-SVID. The broker receives the streamed response before selecting the first SVID (`internal/broker/client.go:272-297`). | Until buffers become unreachable, are reused, or the processes exit. **[ASSUMPTION]** The Go runtime does not provide deterministic erasure of these buffers. |
| **Broker adapter values** | `X509SVID.KeyDER` holds the unencrypted PKCS#8 DER key (`internal/broker/client.go:102-115,348-356`). `exchangePEM` creates the PEM form (`cmd/incus-spiffe-broker/service.go:1268-1298`). | Through conversion and response construction; old DER and PEM allocations can remain in the Go heap until collection or process exit. **[ASSUMPTION]** Collection is not zeroization. |
| **Broker JSON encoder** | `exchangeKeyPEM.MarshalJSON` converts the PEM bytes to a JSON string for the one successful redemption response (`cmd/incus-spiffe-broker/service.go:373-382,449-475`). | While encoding and writing the HTTP response. The current `slog` path redacts, but a future JSON-marshalling logger would reveal the key. |
| **TLS and userspace network buffers** | The JSON response is plaintext before TLS encryption and after TLS decryption. | During delivery and until buffers are reused or released. A forward HTTPS proxy sees ciphertext; a TLS terminator holding the pinned broker key necessarily sees plaintext. **[ASSUMPTION]** Process memory can also be dumped while these bytes remain. |
| **Guest `curl` memory** | `curl` receives and writes the redemption body. | From TLS receipt through response-file completion and buffer reuse. |
| **Guest `jq` memory** | `jq` parses the response and emits the chain, key, and bundle into separate files. | During each extraction. The harness avoids a shell variable, but that does not erase `jq`'s process memory (`spike/p9/guest-agent-bootstrap.sh:301-315,671-703`). |
| **Guest `openssl` memory** | `openssl` parses the key and certificate and compares their public keys before agent startup. | During validation (`spike/p9/guest-agent-bootstrap.sh:705-721`). |
| **Guest `spire-agent` and `x509pop` memory** | The plugin loads the keypair and signs the proof-of-possession challenge. | Initial attestation and until the plugin's objects become unreachable, collection occurs, or the process exits. The source-pinned loader and re-attestation behavior are recorded in `X509POP_BRIEF.md:68-104,360-390`. |
| **Guest tmpfs files** | The complete redemption body, certificate chain, private key, and bundle exist in the mounted tmpfs from redemption through extraction and initial attestation. | The live harness removed the response after extraction and removed the remaining material after attestation; `key-01-shred-verification.txt` records the final namespace state. tmpfs pages can still swap. |

The persistent agent data directory held the public bundle and certificate state. With `AGENT_KEY_MANAGER=memory`, it did not hold the exchange key or the distinct node-SVID private key (`restart-01-agent-process.txt`). This observed filesystem state does not prove that no copy reached swap, a crash dump, a hypervisor memory capture, or an earlier process buffer.

`shred` on tmpfs overwrites pages and unlinks names; it is not cryptographic erasure. The harness implementation says this directly at `spike/p9/guest-agent-bootstrap.sh:369-377`. The live verification proves that the mount was gone and the named files were absent (`key-01-shred-verification.txt`). It does not prove physical-media overwrite.

## Operational semantics production must resolve

### Node re-attestation versus the shred policy

The SPIRE 1.15.2 `x509pop` server returns `CanReattest: true`. On node-SVID rotation, a re-attestable agent performs full node attestation, and the agent plugin reloads `certificate_path` and `private_key_path` on each attestation (`X509POP_BRIEF.md:360-390`). The spike removes both paths immediately after initial attestation (`spike/p9/guest-agent-bootstrap.sh:380-425`).

The live process restart failed before it could serve a Workload API:

```text
unable to load keypair: open /run/spike-exchange/svid.pem: no such file or directory
```

That result is in `restart-01-agent-process.txt`. Restoring service required a fresh nonce and a complete bootstrap. The live run therefore proves a **fresh credential per agent start or boot** policy. It does not prove sustainable re-attestation for an indefinitely running process.

**[ASSUMPTION]** Source behavior says an in-process node re-attestation after the exchange files have been removed will also fail. P9 did not force that event. Production must add a mechanism that places a fresh, valid exchange credential at the configured paths before every node re-attestation, or select a different node lifecycle whose persistence and revocation tradeoffs are explicit. “Fresh nonce per boot” alone is insufficient.

### Burned-nonce retry and denial of service

The reviewed path commits nonce consumption before it clears the config key, derives selectors, or calls the Broker API (`cmd/incus-spiffe-broker/service.go:798-858`). A Broker failure is then classified as `outcome=burned`; the code states that no retry of that nonce can succeed (`cmd/incus-spiffe-broker/service.go:964-990`). P9 observed this naturally: guest B's valid nonce reached the Broker path, the Broker returned no SVID, the service answered `503`, and the nonce was burned (`negative-02-guest-b.txt`).

A `500` or `503` after consumption is therefore retryable only at the **operation** level with a newly minted nonce. It is never retryable with the same nonce. The reviewed harness called `503` “Retryable” without making that distinction (`spike/p9/guest-agent-bootstrap.sh:571-579`).

There is a second delivery boundary. In the reviewed code, an exchange SVID could be issued and the nonce spent, then HTTP response delivery could fail. The client would receive no credential, while the service had already logged `outcome=granted` (`cmd/incus-spiffe-broker/service.go:901-926`). The phase-local code fix separates successful delivery from this case, but production still needs a protocol-level answer for interrupted delivery.

**[ASSUMPTION]** An attacker who can force Broker failures during valid redemptions can deliberately consume available nonces without delivering credentials. A stolen nonce holder can also burn the nonce by redeeming while issuance is unavailable. Production must add:

- one machine-readable contract that marks post-consumption failure as terminal for that nonce;
- client behavior that discards the payload and obtains a fresh mint rather than retrying it;
- bounded automated reminting so repeated burns do not create an unbounded mint loop;
- monitoring and rate controls for burned outcomes; and
- a deliberate decision on whether credential issuance and response delivery need a durable, idempotent handoff.

### Workload-SVID rotation is not node-SVID re-attestation

`workload-02-fetch-and-rotation.txt` shows two workload certificates with different serials and the same workload SPIFFE ID. This proves that the running guest agent refreshed a workload SVID through the Workload API. The fetch logic and serial comparison are at `spike/p9/guest-workload-check.sh:251-297,300-372`.

That rotation does **not** show that the guest agent rotated its node SVID or re-ran `x509pop`. A workload SVID can rotate while the existing node SVID remains valid. Production acceptance must test node lifecycle separately: force or wait for node-SVID re-attestation, record the node certificate change, and verify both the absent-credential failure and the chosen fresh-credential restoration. The P9 workload rotation result must not be cited as proof of node re-attestation.

## Supported versus asserted

### Supported by the reviewed code and P9 live evidence

| Claim | Support and limit |
|---|---|
| **The guest cannot select its own Incus identity in the redemption body.** | The service loads the server-side nonce record, resolves its bound UUID against Incus, and atomically redeems against that live record (`cmd/incus-spiffe-broker/service.go:785-858`). P9 `chain-03-guest-bootstrap.txt` shows host-derived selectors. This does not close theft of the bearer nonce. |
| **The Broker reference contains the consumed binding, not guest-supplied selectors.** | `fetchExchange` constructs `IncusInstanceReference` from the consumed UUID and project (`cmd/incus-spiffe-broker/service.go:929-961`). The host attestor independently derives selectors before the server matches a registration entry. |
| **The code can deliver material in the format SPIRE 1.15.2 `x509pop` consumes.** | The adapter receives DER key, chain, and bundle (`internal/broker/client.go:102-115,348-356`); the service parses and PEM-encodes them (`cmd/incus-spiffe-broker/service.go:1268-1312`). `chain-03-guest-bootstrap.txt` proves the live credential completed `x509pop`. |
| **The live P9 exchange entry was parented to the physically attested host node.** | `deploy-03-entries.txt` shows the exchange entry's parent is the `tpm_devid` node and its selector is the target instance UUID. This is a live configuration fact, not a property enforced by the broker code. |
| **The live broker had the authorized SVID and reached the active host agent.** | `deploy-04-config-and-startup.txt`, `chain-03-guest-bootstrap.txt`, and `chain-04-agent-list.txt` show the authorized broker ID, successful Broker request, and both nodes. This fact must be re-established for each deployment. |
| **The exchange identity mapped to the expected guest node identity and trust domain in this run.** | `chain-03-guest-bootstrap.txt` and `chain-04-agent-list.txt` show the exchange and derived node IDs. `X509POP_BRIEF.md:13-32,106-176` records the source-pinned mapping and trust verification contract. |
| **A root caller obtained and rotated a workload SVID through the standard guest Workload API.** | `workload-02-fetch-and-rotation.txt` shows issuance and a new workload certificate serial over `/tmp/spire-agent/public/api.sock`. This is the narrow result actually observed. |
| **The selected memory-key policy requires a fresh bootstrap after restart.** | `restart-01-agent-process.txt` records failure with the missing exchange certificate path and successful restart after a fresh nonce. `restart-02-guest-reboot.txt` records the same fresh-credential-per-boot outcome after VM restart. |
| **The broker was pinned before the nonce was sent.** | The harness obtains and checks the public leaf before `redeem` (`spike/p9/guest-agent-bootstrap.sh:500-548,588-667`); `chain-03-guest-bootstrap.txt` records the order. |

The live successful run used explicit `CHAIN_JQ`, `KEY_JQ`, and `BUNDLE_JQ` overrides because the reviewed default harness did not accept the producer's field names. `chain-02-field-name-mismatch.txt` records the failed first redemption and `chain-03-guest-bootstrap.txt` records the corrected run. The phase-local harness fix removes the need for that workaround, but the transcript must remain part of the record.

### Asserted, deployment-dependent, or not proved by P9

| Claim | Assessment |
|---|---|
| **Every P9 exchange entry has the required physically attested parent.** | **Deployment-dependent.** The code cannot establish registration-entry parentage. P9 proved the specific live entry in `deploy-03-entries.txt`; production must verify this configuration on every deployment. An entry with the wrong parent breaks the independent-attestation chain. |
| **A non-root in-guest application can reach the Workload API and obtain the expected SVID.** | **Not proved by the existing live run.** The entry used `unix:uid:0` (`workload-01-entry.txt`), the harness was invoked through root `incus exec`, and `workload-02-fetch-and-rotation.txt` contains no non-root caller proof. The harness fix requires a non-root execution, but new live evidence is required before this claim can pass. |
| **Workload-SVID rotation proves node-SVID re-attestation.** | **False.** The observed serial change is for the workload SVID only. No forced or expiry-driven node re-attestation occurred. Source predicts that the missing exchange paths will fail (`X509POP_BRIEF.md:360-392`). |
| **Fresh credential per boot supports an indefinitely running guest agent.** | **Not proved and contradicted by the source-pinned lifecycle.** `CanReattest=true` eventually selects full `x509pop` again. P9 did not observe that in-process event. |
| **The exchange key never reaches persistent media.** | **Not supported.** There is no intentional persistent regular-file write, but tmpfs can swap and process pages can enter dumps. The defensible claim is narrower: the live filesystem check found no exchange-key file after reclaim. |
| **`shred` cryptographically erases tmpfs content.** | **False.** It overwrites pages and unlinks names. `key-01-shred-verification.txt` proves namespace cleanup, not cryptographic erasure. |
| **The broker authority is acceptably isolated because the Incus adapters are narrow.** | **False as a process-boundary claim.** Process compromise exposes the raw credentials, sockets, and broker SVID source. Adapter method allowlists do not constrain a holder of the underlying credentials. |
| **The current redaction type prevents every future logging leak.** | **False.** Current `fmt` and `slog` paths redact, but `exchangeKeyPEM.MarshalJSON` deliberately reveals. Any future JSON-marshalling logger must be treated as a key-delivery sink and reviewed accordingly. |

P9 proves H8 for the specific live chain, subject to the root-only scope of the workload check. It does not close SEC-009, make the broker a safe production trust boundary, prove node re-attestation, or prove cryptographic erasure. Those are go/no-go decisions, not silent substitutions under the architecture-contradiction protocol.

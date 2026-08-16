# P3 Evidence — Host SPIRE Agent and Physical `tpm_devid` Attestation (critical gate)

**Captured:** 2026-08-16 15:51 PDT
**Host:** `ovh-incusos` (`147.135.105.83:8443`), IncusOS `202608102114`, Incus `7.3`, SPIRE `1.15.2`
**Decision:** **GATE G3 PASSES with one documented coverage gap.** Physical-TPM node attestation works end to end, persists across container restart and host reboot, and all four negative cases fail closed. Custom Incus attestor and Broker development is now permitted.

## Scope

P3 ran the upstream SPIRE Agent as an Incus OCI application container with the host's physical TPM passed through as a `unix-char` device, attesting to the P2 server using the P1 TPM-resident DevID. This is the hypothesis H3 gate: does `tpm_devid` node attestation work against a real TPM, positively and negatively, and survive restarts.

## Acceptance result (Gate G3)

| Criterion | Result | Evidence |
|---|---|---|
| Agent attests against the physical TPM | PASS | `Node attestation was successful … spiffe_id="spiffe://spike.incus.internal/spire/agent/tpm_devid/fee6de975fb82fdbd3c7b7ea7e0b752412469fd0"` |
| Server records the node with expected selectors | PASS | 4 selectors, all independently re-derived below |
| Persistence across agent container restart | PASS | `SVID loaded` from disk, no re-attestation, serial unchanged |
| Persistence across full host reboot | PASS | Auto-restored, `SVID loaded`, same serial, no manual action |
| Negative (a) untrusted DevID CA | FAILS CLOSED | `unable to verify DevID signature: … x509: certificate signed by unknown authority` |
| Negative (b) foreign-TPM DevID triplet | FAILS CLOSED | `cannot load DevID key on TPM: tpm2.Load failed: … error code 0x1f : integrity check failed` |
| Negative (c) no `/dev/tpmrm0` | FAILS CLOSED | `cannot open TPM at "/dev/tpmrm0": stat /dev/tpmrm0: no such file or directory` |
| Negative (d) tampered `devid.pem` | FAILS CLOSED | `x509: certificate signed by unknown authority (possibly because of "crypto/rsa: verification error" …)` |
| Post-reboot host invariant | PASS | `tpm_status=ok`, fully trusted, root and swap `unlocked (TPM)`, Secure Boot enabled |
| TPM namespace unchanged | PASS | Identical to the P0 baseline; DA counter still `0x0` |

**Coverage gap, stated plainly:** negative case (b) fails locally at TPM key load rather than at the server's proof-of-residency check. See [Negative case (b)](#negative-case-b--foreign-software-tpm-devid-triplet) for why that is the correct and stronger result here, and what remains unexercised.

## Node identity produced

| Property | Value |
|---|---|
| SPIFFE ID | `spiffe://spike.incus.internal/spire/agent/tpm_devid/fee6de975fb82fdbd3c7b7ea7e0b752412469fd0` |
| Attestation type | `tpm_devid` |
| Can re-attest | `true` |
| Agent version | `1.15.2` |
| Selectors | `tpm_devid:subject:cn:spike-host-devid` |
| | `tpm_devid:issuer:cn:spike DevID issuing CA` |
| | `tpm_devid:ca:fingerprint:2e6938a538745fd341bea0267bdbea2723fcd035` |
| | `tpm_devid:ca:fingerprint:7b135f9064faa41a9687165007807c073689bc79` |

Every value was re-derived independently from the certificate rather than trusted from the server output:

```text
devid leaf SHA1:    fee6de975fb82fdbd3c7b7ea7e0b752412469fd0   -> matches the SPIFFE ID path
issuing CA SHA1:    2e6938a538745fd341bea0267bdbea2723fcd035   -> matches selector 1
spike root CA SHA1: 7b135f9064faa41a9687165007807c073689bc79   -> matches selector 2
```

**Documentation discrepancy found.** The SPIRE 1.15.2 server plugin doc lists the fingerprint selector as `tpm_devid:fingerprint:<hex>`. The implementation actually emits `tpm_devid:ca:fingerprint:<hex>`. The plan's Appendix F and the P2 handoff both carried the documented form. Any registration entry written against `tpm_devid:fingerprint:` would silently never match. Use the observed form.

Also confirmed: the fingerprint selectors cover **every CA in the chain excluding the leaf** — here both the issuing CA and the root — not just the immediate issuer.

## Topology introduced

| Object | Type | Purpose | Retained |
|---|---|---|---|
| `spire-agent` | Incus OCI application container | Host SPIRE Agent with TPM passthrough | Yes, until P11 |
| `spike-p3-stage` | Incus OCI application container (Debian + openssl, tpm2-tools, swtpm, python3) | Config staging and negative-artifact factory | Yes, stopped; TPM device detached |
| `spike-agent-neg-{a,b,c,d}` | Incus OCI application containers | One per negative case, isolated data dirs | No, deleted; logs preserved |

Agent image pinning:

| Reference | Digest |
|---|---|
| `ghcr.io/spiffe/spire-agent:1.15.2` index | `sha256:1d042e4040466686e0ee46f74981ff2167c86adfadca19b3835946f4d6047536` |
| `linux/amd64` manifest (in use) | `sha256:5fbe8ac3ad5b1cff355bcf40badb579691e3c8de6cc4c3b8f6792e51336d12a5` |
| `linux/arm64` manifest | `sha256:fc88a924829510884c347533afaf42594bd203a5dca080901461ccd6b40ba3ec` |

Upstream image config: entrypoint `/opt/spire/bin/spire-agent run`, **user `0:0`**, workdir `/opt/spire`.

**This corrects the P2 handoff.** P2 predicted P3 would need to chown the DevID blobs because the server image runs as uid 1000. The agent image runs as root, so the P1 artifacts (`root:root`, mode `0600`) were readable as-is with no ownership change and no `security.shifted` on `spike-spire-agent-state`. Worth carrying into the architecture: the two upstream SPIRE images do **not** share a runtime user, so any production packaging must state the expected uid per component rather than assume one.

TPM device wiring, identical to the Mac-lab pattern:

```text
incus config device add ovh-incusos:spire-agent tpm unix-char source=/dev/tpmrm0 path=/dev/tpmrm0
```

## Agent configuration

Full file: [`agent.conf.txt`](agent.conf.txt). Instance snapshot: [`spire-agent-instance-config.yaml.txt`](spire-agent-instance-config.yaml.txt).

| Setting | Value | Rationale |
|---|---|---|
| `server_address` / `server_port` | `10.55.156.67` / `8081` | P2 server over `incusbr0`. |
| `trust_bundle_path` | `/spike/conf/agent-trust-bundle.pem` | Real bootstrap trust, no `insecure_bootstrap`. Bundle fingerprint `493bac43…` matches the P2 server bundle exactly. |
| `data_dir` | `/spike/agent-data` | On the encrypted volume, so SVID state survives reboot. |
| `KeyManager "disk"` | `directory = "/spike/agent-data"` | Persists the agent key; a memory manager would have forced re-attestation on every restart and hidden the persistence property. |
| `socket_path` | `/spike/run/api.sock` | On the shared volume so P4 workloads can reach the Workload API without network exposure. |
| `tpm_devid` hierarchy passwords | omitted | P0 observed `ownerAuthSet`, `endorsementAuthSet`, `lockoutAuthSet` all unset. |

## Positive path

Captured log: [`spire-agent-console.log.txt`](spire-agent-console.log.txt).

```text
INFO Starting agent                    data_dir=/spike/agent-data version=1.15.2
INFO Plugin loaded                     plugin_name=tpm_devid plugin_type=NodeAttestor
INFO Plugin loaded                     plugin_name=disk plugin_type=KeyManager
INFO Plugin loaded                     plugin_name=unix plugin_type=WorkloadAttestor
INFO Bundle loaded                     trust_domain_id="spiffe://spike.incus.internal"
DEBU No pre-existing agent SVID found. Will perform node attestation
INFO SVID is not found. Starting node attestation
INFO Node attestation was successful   reattestable=true spiffe_id="spiffe://spike.incus.internal/spire/agent/tpm_devid/fee6de975fb82fdbd3c7b7ea7e0b752412469fd0"
INFO Success after 33.477260869s attempts=1
INFO Starting Workload and SDS APIs    address=/spike/run/api.sock network=unix
INFO Health check recovered            check=agent failures=26
```

Server-side, from the same run:

```text
INFO Agent attestation request completed  address="10.55.156.104:40024"
     agent_id="spiffe://spike.incus.internal/spire/agent/tpm_devid/fee6de975fb82fdbd3c7b7ea7e0b752412469fd0"
     authorized_as=nobody method=AttestAgent node_attestor_type=tpm_devid service=agent.v1.Agent
```

Agent health from `spike-probe`: `/live` 200, `/ready` 200, body `{"agent":{}}`.

### Attestation cost is significant and reproducible

Full attestation was measured three separate times: **33.32 s, 33.46 s, 33.48 s**. During that window the agent's health check reports `workload api is unavailable` and fails 26 times before recovering.

That is a real operational property, not noise. The physical TPM work in one attestation is: recreate the SRK, load the DevID key, create and load an attestation key, regenerate the EK, read the EK certificate from NV, certify the DevID with the AK, sign the server nonce, and solve credential activation. On this Nuvoton NPCT6xx that costs roughly half a minute.

Architecture consequences to carry forward:

- Any readiness gate or supervisor timeout must allow well over 35 seconds for a cold agent start.
- Restart from persisted state is effectively instant by comparison, so **SVID persistence is what keeps restarts cheap**. Losing the data dir costs a full attestation.
- Fan-out matters: many agents attesting simultaneously against one physical TPM would serialize. Not applicable to a one-agent-per-host design, but it rules out designs that attest per workload against the host TPM.

### Re-attestation works

Deleting `agent-data.json` from the data dir and restarting forced a complete fresh attestation:

```text
DEBU No pre-existing agent SVID found. Will perform node attestation
INFO Node attestation was successful   reattestable=true spiffe_id="…/tpm_devid/fee6de975fb82fdbd3c7b7ea7e0b752412469fd0"
```

The SPIFFE ID is stable across re-attestation because it derives from the DevID certificate, while the SVID serial and expiry change:

| Attestation | Serial | Expiry |
|---|---|---|
| First | `313682679650608302849566418729878494992` | 2026-08-16 23:34:22 UTC |
| After forced re-attestation | `307637126702822959610300583484564075048` | 2026-08-16 23:40:04 UTC |

Useful discovery about state layout: the agent SVID is **not** stored as `agent_svid.der` in SPIRE 1.15.2. The data dir contains `agent-data.json` (SVID and bundle state) and `keys.json` (the disk key manager's private key). An earlier attempt to force re-attestation by deleting `agent_svid.der` was a no-op; the file does not exist. Any production runbook that clears agent state must target `agent-data.json`.

## Persistence

### Agent container restart

```text
INFO SVID loaded   spiffe_id="spiffe://spike.incus.internal/spire/agent/tpm_devid/fee6de975fb82fdbd3c7b7ea7e0b752412469fd0"
INFO Starting Workload and SDS APIs   address=/spike/run/api.sock network=unix
```

No attestation, no TPM work, serial unchanged at `313682679650608302849566418729878494992`.

### Host reboot

After `incus admin os system reboot ovh-incusos: --force`:

- `spire-agent`, `spire-server`, `spike-probe`, and `spike-p3-stage` all returned to `RUNNING` unaided, keeping their addresses.
- Agent log: `Starting agent` then `SVID loaded` at `INFO[0000]`, Workload API up at `INFO[0004]`.
- Server still lists exactly one attested agent with the same serial.
- Agent `/ready` 200.
- Host invariant: `{"tpm_status":"ok","trusted":true,"volumes":["unlocked (TPM)","unlocked (TPM)"],"secure_boot":true}`.

The host has now been rebooted three times across P1–P3 with the TPM in active use by containers, and IncusOS trusted unlock has held every time.

## Negative cases

Each case ran in its own throwaway container with an isolated `data_dir`, so the working agent's state was never touched. The working agent stayed attested throughout. Build scripts: [`negatives-build-ad.sh.txt`](negatives-build-ad.sh.txt), [`negatives-build-b.sh.txt`](negatives-build-b.sh.txt), [`negatives-build-b2.sh.txt`](negatives-build-b2.sh.txt).

### Negative case (a) — DevID certified by an untrusted CA

Construction: a throwaway rogue two-tier CA certified **the real TPM DevID public key** using `openssl x509 -req -force_pubkey`. The private key still lives in the host TPM, so proof-of-possession would succeed; only the chain is wrong. Verified before the test that the rogue leaf's public key is byte-identical to the real DevID key.

Agent log ([`spike-agent-neg-a-console.log.txt`](spike-agent-neg-a-console.log.txt)):

```text
WARN Failed to retrieve attestation result
     error="failed to receive attestation response: rpc error: code = InvalidArgument
     desc = nodeattestor(tpm_devid): unable to verify DevID signature: verification failed:
     x509: certificate signed by unknown authority"
```

Server log:

```text
ERRO Invalid argument: nodeattestor(tpm_devid): unable to verify DevID signature: verification failed:
     x509: certificate signed by unknown authority
     caller_addr="10.55.156.73:47904" method=AttestAgent node_attestor_type=tpm_devid
     request_id=5295116e-0edf-43d0-8726-83977a90a368
```

This isolates the `devid_ca_path` chain check exactly as intended. Attested agent count stayed at 1.

### Negative case (b) — foreign software-TPM DevID triplet

Construction: a `swtpm` 0.7.1 software TPM (manufacturer `IBM`, entirely separate from the host TPM) created an SRK using SPIRE's H-1 template and a DevID signing key with the same template shape as P1. The blobs were exported with `tpm2-tools` and converted to SPIRE format by stripping the 2-byte `TPM2B` size prefix — the same format finding recorded in P1. The **genuine** spike DevID issuing CA then certified the foreign public key, so:

```text
case-b chain verifies against the real spike root:
  /state/negatives/case-b/devid.pem: OK
case-b key differs from the real host DevID key:
  yes, different key
```

Blob sizes: foreign pub 280 bytes (identical to the real one), foreign priv 222 bytes versus the real 190.

Result, running against the **real** host TPM ([`spike-agent-neg-b-console.log.txt`](spike-agent-neg-b-console.log.txt)):

```text
WARN Failed to retrieve attestation result
     error="rpc error: code = Internal desc = nodeattestor(tpm_devid): unable to start a new TPM session:
     cannot load DevID key on TPM: tpm2.Load failed: parameter 1, error code 0x1f : integrity check failed"
```

The failure is **local and absolute**: `TPM_RC_INTEGRITY`. The private blob is sealed under the originating TPM's storage root key seed, and the key template carries `fixedTPM|fixedParent`, so this host's TPM refuses to load it. No attestation payload ever reaches the server, which is why the server log shows no error for this case.

**What this proves:** DevID credentials are non-migratable between TPMs. Stealing the blob triplet and a validly-issued certificate is not sufficient to impersonate the host.

**What it does not exercise:** the server-side proof-of-residency path, specifically `verifyEKsMatch` comparing the EK certificate against the regenerated EK, and credential activation against a mismatched EK. Reaching that requires an agent whose TPM is the software TPM while it presents a foreign EK certificate. That is not achievable here: the agent takes a device path, and exposing `swtpm` as `/dev/tpmN` needs the kernel vTPM proxy (`/dev/vtpmx`, `tpm_vtpm_proxy`, `CAP_SYS_ADMIN`) or CUSE, none of which are available to an unprivileged container on IncusOS. Deliberately not pursued: it would mean privileged access on the same host whose disk unlock depends on this TPM.

Two concrete ways to close the gap later, in preference order:

1. Write a small test client that speaks `agent.v1.Agent/AttestAgent` directly with a hand-built payload: real EK certificate, software-TPM AK and DevID. This isolates server-side residency verification with no privileged host access.
2. Run the case on a throwaway machine with a vTPM-proxy-capable kernel, where a software TPM can be presented as a device.

**Safety result worth recording:** the DA counter was `0x0` immediately before this case and `0x0` immediately after. A `TPM2_Load` integrity failure does **not** increment the dictionary-attack counter on this TPM. The case was still deliberately stopped after the first attempt, because the agent retries on a backoff loop and a counter-incrementing failure mode would have climbed toward the limit of 10.

### Negative case (c) — TPM device not attached

The container was created with the state volume but **no** `unix-char` device. Confirmed device list contained only `state`.

Agent log ([`spike-agent-neg-c-console.log.txt`](spike-agent-neg-c-console.log.txt)):

```text
WARN Failed to retrieve attestation result
     error="rpc error: code = Internal desc = nodeattestor(tpm_devid): unable to start a new TPM session:
     cannot open TPM at \"/dev/tpmrm0\": stat /dev/tpmrm0: no such file or directory"
```

Retry intervals grew `10.2s → 16.3s`, so the agent backs off rather than spinning. Attestation cannot complete without the device, and the failure names the exact missing path.

### Negative case (d) — tampered `devid.pem`

Construction: a copy of the genuine chain with a single base64 character altered in the leaf certificate body. `openssl verify` against the real spike root fails with `certificate signature failure` and an RSA padding error, confirming the tamper is cryptographic rather than structural — the certificate still parses.

Agent log ([`spike-agent-neg-d-console.log.txt`](spike-agent-neg-d-console.log.txt)):

```text
WARN Failed to retrieve attestation result
     error="… nodeattestor(tpm_devid): unable to verify DevID signature: verification failed:
     x509: certificate signed by unknown authority (possibly because of \"crypto/rsa: verification error\"
     while trying to verify candidate authority certificate \"spike DevID issuing CA\")"
```

The rejection reason is distinguishable from case (a): here the server found the correct candidate issuer, `spike DevID issuing CA`, and the RSA signature check failed. Case (a) had no candidate issuer at all. Both surface as `InvalidArgument`, so operational tooling should match on the inner text, not the gRPC code.

## TPM state after the whole phase

| Property | P0 baseline | After P3 |
|---|---|---|
| Persistent handles | `0x81000001` | `0x81000001` |
| NV indices | `0x1C00002`, `0x1C0000A` | `0x1C00002`, `0x1C0000A` |
| `TPM2_PT_HR_PERSISTENT` | `0x1` | `0x1` |
| `TPM2_PT_HR_NV_INDEX` | `0x2` | `0x2` |
| `TPM2_PT_NV_COUNTERS` | `0x0` | `0x0` |
| `ownerAuthSet` / `endorsementAuthSet` / `lockoutAuthSet` | `0` / `0` / `0` | `0` / `0` / `0` |
| `inLockout` | false | false |
| `TPM2_PT_LOCKOUT_COUNTER` | `0x0` | `0x0` |

Captured: [`tpm-final-inventory.txt`](tpm-final-inventory.txt), [`host-security-final.json.txt`](host-security-final.json.txt).

Three successful attestations plus four negative cases moved nothing. H4's zero-persistent-footprint result from P1 holds under real attestation load.

## Operational findings for the architecture document

1. **Console logs are ephemeral and destructive to read.** `incus console --show-log` on a running OCI application container returned the buffer once and then returned empty on the next call. A positive-path log had to be regenerated by forcing re-attestation in order to capture a complete artifact. Any production design needs a real log sink; do not rely on the Incus console ring for audit.
2. **`incus file push` preserves the *local* uid.** Files pushed from the Mac landed as uid 501 inside the container and needed an explicit `chown`. Staging steps must set ownership deliberately.
3. **The two SPIRE images run as different users:** server `1000:1000`, agent `0:0`.
4. **Attestation takes ~33.5 s** on this TPM, reproducibly, and the agent is not ready during that window.
5. **Agent state file is `agent-data.json`**, not `agent_svid.der`.
6. **Selector name is `tpm_devid:ca:fingerprint:`**, contradicting the upstream doc.
7. **`TPM2_Load` integrity failures do not move the DA counter** on this Nuvoton part, so a mis-provisioned agent retry loop is not a lockout risk. This should be re-verified on any different TPM vendor before relying on it.
8. **Agent retry backoff is bounded and grows** (`5s → 10s → 16s`), so a persistently misconfigured agent will not hammer the server or the TPM.

## Commands exercised

```text
skopeo inspect --raw docker://ghcr.io/spiffe/spire-agent:1.15.2
skopeo inspect --config --override-os linux --override-arch amd64 docker://ghcr.io/spiffe/spire-agent:1.15.2

incus exec ovh-incusos:spire-server -- /opt/spire/bin/spire-server bundle show -socketPath ... > agent-trust-bundle.pem
incus init docker:debian:trixie ovh-incusos:spike-p3-stage -c 'oci.entrypoint=sleep infinity'
incus config device add ovh-incusos:spike-p3-stage state disk pool=local source=spike-spire-agent-state path=/state
incus config device add ovh-incusos:spike-p3-stage ca disk pool=local source=spike-ca-state path=/ca

incus init ghcr:spiffe/spire-agent:1.15.2 ovh-incusos:spire-agent \
  -c 'oci.entrypoint=/opt/spire/bin/spire-agent run -config /spike/conf/agent.conf'
incus config device add ovh-incusos:spire-agent state disk pool=local source=spike-spire-agent-state path=/spike
incus config device add ovh-incusos:spire-agent tpm unix-char source=/dev/tpmrm0 path=/dev/tpmrm0
incus start ovh-incusos:spire-agent
incus restart ovh-incusos:spire-agent
incus admin os system reboot ovh-incusos: --force

incus exec ovh-incusos:spire-server -- /opt/spire/bin/spire-server agent list -socketPath ...
incus exec ovh-incusos:spire-server -- /opt/spire/bin/spire-server agent show -spiffeID ... -socketPath ...
incus exec ovh-incusos:spire-server -- /opt/spire/bin/spire-server entry count -socketPath ...

# per negative case, x in {a,b,c,d}
incus init ghcr:spiffe/spire-agent:1.15.2 ovh-incusos:spike-agent-neg-x \
  -c 'oci.entrypoint=/opt/spire/bin/spire-agent run -config /spike/negatives/case-x/agent.conf'
incus delete ovh-incusos:spike-agent-neg-x --force

# software TPM for case (b)
swtpm socket --tpm2 --tpmstate dir=/tmp/swtpm-state --server type=tcp,port=2321 --ctrl type=tcp,port=2322 \
  --flags not-need-init,startup-clear --daemon
tpm2_createprimary -C o -g sha256 -G rsa2048 -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt'
tpm2_create -C srk.ctx -g sha256 -G rsa2048:rsassa-sha256 -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign'
tail -c +3 foreign-devid.pub.tpm2b > devid.pub.blob   # strip TPM2B size prefix
openssl x509 -req -force_pubkey foreign-devid-pub.pem -CA spike-devid-ca.pem -CAkey spike-devid-ca.key
```

One `swtpm` hiccup worth noting: `tpm2_readpublic` on a saved context failed with `out of memory for object contexts` until transient contexts were flushed. Software TPMs have far fewer object slots than the hardware part.

## Cleanup and retained state

- Deleted all four negative agent containers; their console logs are preserved in this directory.
- Retained, per instruction to keep evidence: the negative artifacts on `spike-spire-agent-state` under `/spike/negatives/` — `case-a` rogue chain, `case-b` foreign triplet, `case-d` tampered chain, `rogue-ca` throwaway CA with its private keys, per-case `agent.conf`, and `saved/agent-data.json.bak`.
- `spike-p3-stage` is stopped and its TPM device has been detached; it still has the tooling needed by later phases.
- The working `spire-agent` is running and attested. `spire-server` reports 1 attested agent, 0 registration entries.
- The software TPM and its state directory were destroyed inside the staging container.

**Security note on retained material:** `/spike/negatives/rogue-ca/` holds private keys for a CA that is deliberately *not* trusted by the server, and `case-b` holds blobs for a key that this TPM cannot load. Neither grants any authority in this trust domain. Both are on the P11 teardown list. No genuine private key, TPM blob, or recovery value appears in this journal.

## Teardown inventory additions

| Class | Object | Removal |
|---|---|---|
| 2 | `spire-agent` container | P11, after guest phases |
| 3 | `/spike/negatives/**` on `spike-spire-agent-state` (rogue CA keys, foreign triplet, tampered chain) | P11 with the volume |
| 5 | `spike-p3-stage` container (stopped) | P11 |
| 5 | Host image `spire-agent` amd64 `sha256:5fbe8ac3…` | P11 |

## Gate decision

**G3 passes.** The host identity claim is proven on real hardware: a TPM-resident DevID, non-migratable between TPMs, attested against a manufacturer-rooted endorsement chain, producing a stable SPIFFE ID that survives restart and reboot, with all four failure modes rejected and no TPM state drift.

Per the plan, custom Incus attestor and Broker development is now permitted. The one open item, server-side residency verification against a mismatched EK, is a test-coverage gap rather than an architectural unknown, and it does not block P4 onward.

## Handoff to P4

The Workload API is live at `/spike/run/api.sock` on the `spike-spire-agent-state` volume. A workload container can mount that volume and reach the socket with no network exposure. The `unix` workload attestor is loaded and ready for the P4 baseline entry, which must be parented to:

```text
spiffe://spike.incus.internal/spire/agent/tpm_devid/fee6de975fb82fdbd3c7b7ea7e0b752412469fd0
```

Reminder for P4 registration entries: use `tpm_devid:ca:fingerprint:` if a CA-based selector is wanted, and remember the agent SVID TTL is 1 hour with a 24-hour CA TTL, so an authority rotation is still expected mid-spike.

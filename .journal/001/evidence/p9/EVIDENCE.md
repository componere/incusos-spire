# P9 — Guest `x509pop` bootstrap, guest-local SPIRE Agent, guest Workload API, live run — 2026-08-17 15:27–15:45 UTC on `ovh-incusos` (`ns1001912.ip-147-135-105.us`, IncusOS `202608102114`, Incus 7.3, x86_64)

Companion document, not restated here:
[`X509POP_BRIEF.md`](./X509POP_BRIEF.md) — the source-cited `spiffe/spire` `v1.15.2` contract for
`x509pop` SPIFFE mode. Three of its findings were load-bearing for this run and all three held
live: the server key is `spiffe_prefix` rather than the documented `svid_prefix`; the real default
template is `/{{ .PluginName }}/{{ .SVIDPathTrimmed }}` with a leading slash; and a SPIRE-issued
X509-SVID is usable as the `x509pop` exchange credential. The live server sets only
`mode = "spiffe"` and takes both defaults, so nothing needed changing — and nothing was changed.

## Scope

Redeploy `cmd/incus-spiffe-broker` with exchange-SVID delivery, register the exchange entry the
broker's Broker API request must match, and prove the whole chain on live hardware: nonce
redemption yields a broker-obtained exchange SVID, a guest-local SPIRE Agent 1.15.2 trades it via
`x509pop` `mode="spiffe"` for its own node identity, and an in-guest application fetches its SVID
from a standard local Workload API and observes a rotation.

In scope: broker redeployment and its new configuration, the exchange registration entry and its
parentage, the positive chain end to end, exchange-key handling and its verified destruction, the
in-guest Workload API, the restart and reboot story, negative checks, cleanup, and an executed
secret scan.

Out of scope: the adversarial and lifecycle matrix (P10), any TPM operation, any host mutation, any
change to the code worktree, any repository gate, any Git command.

Everything below was observed on the live host. Anything not directly observed is marked
`[INFERENCE]`. Per Appendix D — which now covers a **private key** as well as a nonce value — no
nonce secret and no private key appears anywhere in this directory; SPIFFE IDs, certificate serials,
validity windows, fingerprints, selectors, payload digests and HTTP/gRPC codes are recorded instead,
and [§ Secret handling](#secret-handling) shows the scan that was executed to confirm it.

## Acceptance result

| # | Criterion (`SPIKE_PLAN.md` P9) | Verdict | Evidence |
|---|---|---|---|
| **A1** | **An in-guest app obtains the expected SVID from a standard local Workload API** | **PASS** | [`workload-02-fetch-and-rotation.txt`](./workload-02-fetch-and-rotation.txt) — `spiffe://spike.incus.internal/guest/demo` fetched over `/tmp/spire-agent/public/api.sock`, then rotated: serial `CB2E…18C9` → `1BA4…CF25`, SPIFFE ID unchanged |
| **A2** | **The issuance path requires the physically attested host agent** | **PASS** | [`deploy-03-entries.txt`](./deploy-03-entries.txt), [`chain-03-guest-bootstrap.txt`](./chain-03-guest-bootstrap.txt) — the exchange entry's parent is the `tpm_devid` node; the exchange SVID is minted only through that node's Broker API |
| **A3** | **…an authorized broker SVID** | **PASS** | [`deploy-04-config-and-startup.txt`](./deploy-04-config-and-startup.txt) — the broker holds `spiffe://spike.incus.internal/incus-broker`, the single ID in the host agent's `experimental.broker.brokers[]` allow-list, and authorizes the endpoint as the `tpm_devid` node ID |
| **A4** | **…and selectors independently derived from the authoritative Incus record** | **PASS** | [`chain-03-guest-bootstrap.txt`](./chain-03-guest-bootstrap.txt) — six `incus:` selectors returned, all re-derived host-side from live Incus state; the guest supplies none of them |
| **A5** | **The SPIFFE trust chain remains rooted in the trust domain** | **PASS** | [`chain-04-agent-list.txt`](./chain-04-agent-list.txt) — `x509pop` SPIFFE mode verified the exchange chain against the server's **own** bundle; guest node selectors are `x509pop:ca:fingerprint:ef7e6ffe…` and `x509pop:serialnumber:829f56c0…` |
| **A6** | **The server lists the guest node produced by the exchange SVID** | **PASS** | [`chain-04-agent-list.txt`](./chain-04-agent-list.txt) — two attested agents: `…/spire/agent/tpm_devid/fee6de97…` and `…/spire/agent/x509pop/incus/a955ca30-a0dc-4087-a369-37d53d389c5a` |
| **A7** | **Exchange key handling documented and the shred VERIFIED** | **PASS** | [`key-01-shred-verification.txt`](./key-01-shred-verification.txt) — `/run/spike-exchange` is no longer a mount point, the directory is empty, zero `svid.key`/`svid.pem`/`redeem-response*` anywhere, no `PRIVATE KEY` block on any guest filesystem. See [§ Exchange key handling and its tradeoff](#exchange-key-handling-and-its-tradeoff) |
| **A8** | **Restart and reboot behaviour recorded, with an explicit re-attestation story** | **PASS** | [`restart-01-agent-process.txt`](./restart-01-agent-process.txt), [`restart-02-guest-reboot.txt`](./restart-02-guest-reboot.txt) — the spike demonstrates **fresh-credential-per-boot**, not agent-SVID persistence |
| **A9** | **Nonce reuse rejected** | **PASS** | [`negative-01-nonce-reuse.txt`](./negative-01-nonce-reuse.txt) — replay of the same nonce → HTTP `409`, broker reason `nonce already used`, harness exit `11` |
| **A10** | **`spike-guest-b` cannot obtain guest A's node identity through this path** | **PASS** | [`negative-02-guest-b.txt`](./negative-02-guest-b.txt) — B's own socket answers `404`; B redeeming its own nonce resolves only B and never produces a node. The unused-leaked-nonce bearer case is P8 M1, unchanged and now higher-stakes — see [§ Negative checks](#negative-checks) |
| **A11** | **No nonce secret and no private key in the evidence, proven by a scan** | **PASS** | [`secret-scan.txt`](./secret-scan.txt) — mechanical Appendix D rule 4 checks, full 64-hex attribution, and live positive controls for **both** a real nonce secret and a real exchange **private key** |
| **A12** | **Host agent attested and healthy; guests and broker running; host untouched** | **PASS** | [`cleanup-final-state.txt`](./cleanup-final-state.txt) — `tpm_devid` node still attested, `/live` and `/ready` both `200`, broker listening, both guests `RUNNING`, host `system_state_is_trusted: true`, host uptime unbroken |
| **F1** | **Broker's own SVID source does not work cross-container** | **FINDING** | [`deploy-05-workload-api-relay.txt`](./deploy-05-workload-api-relay.txt) — a spike relay was required; see [§ Findings for the architecture](#findings-for-the-architecture) |
| **F2** | **Harness/broker redeem field-name mismatch** — **FIXED at `3f5b7f6`; see A14** | **FINDING (CLOSED)** | [`chain-02-field-name-mismatch.txt`](./chain-02-field-name-mismatch.txt) — cost one nonce, no design impact |
| **F3** | **A Broker-side failure after nonce consumption burns the nonce** — now also **forced deliberately and named to the caller**; see A15 | **MEASURED** | [`negative-02-guest-b.txt`](./negative-02-guest-b.txt) — HTTP `503`, `failure_class=broker_no_svid`, `outcome=burned`; the documented contract, observed naturally |

| **A13** | **Post-fix: deployed binary verified inside the container** | **PASS** | [`postfix-01-redeploy.txt`](./postfix-01-redeploy.txt) — `4ed87f92…fa45`, matched operator-side and by `sha256sum` in the container; socket exposure and credentials unchanged |
| **A14** | **Post-fix: the guest chain completes with NO manual intervention** | **PASS** | [`postfix-02b-clean-run.txt`](./postfix-02b-clean-run.txt) — exit `0`, one nonce, no `CHAIN_JQ`/`KEY_JQ`/`BUNDLE_JQ`, no hand-editing; canonical field names consumed first; node rebuilt after an `agent evict` |
| **A15** | **Post-fix: the burned-nonce condition is named to the caller, and the nonce is really spent** | **PASS** | [`postfix-04-burn.txt`](./postfix-04-burn.txt) — `503` `{"error":"nonce_consumed_without_svid"}` with `outcome=burned failure_class=broker_no_svid`; replay of the same nonce returns the ordinary `409` `{"error":"conflict"}` |
| **A16** | **Post-fix: a NON-ROOT in-guest application is served by the Workload API** | **PASS** | [`postfix-03-workload.txt`](./postfix-03-workload.txt) — `check=issuance` uid 0 → `/guest/demo` and `check=issuance-nonroot` uid 989 → `/guest/demo-app`, different IDs from the same socket |
| **A17** | **Post-fix: `EXCHANGE_RETENTION` measured both ways** | **PASS** | [`postfix-05-retention.txt`](./postfix-05-retention.txt) — `shred`: `unable to load keypair`, agent dead; `keep`: boxed warning, agent re-attests `reattestable=true`. Left in `shred` |
| **A18** | **Post-fix: host untouched, guests and broker running, secret scan clean with working controls** | **PASS** | [`postfix-06-final.txt`](./postfix-06-final.txt), [`postfix-07-secret-scan.txt`](./postfix-07-secret-scan.txt) — plus **finding S1**, a defect in the ORIGINAL scan pattern, disclosed rather than quietly fixed |

**H8 is proven.** Nonce redemption yields a broker-obtained exchange SVID, the guest agent
exchanges it via `x509pop` `mode="spiffe"` for the node identity the v1.15.2 defaults predict, and
an ordinary in-guest application obtains and rotates its own SVID over a standard local Workload
API. The two things the spike does **not** solve — the exchange key's exposure window and the
broker's own SVID source in a container topology — are recorded below as go/no-go input rather than
papered over.

## Deployment

### Binary

| Item | Value |
|---|---|
| Previous binary | `c534af07c95ef333b1a09dabb75367c6f66ab5cc01b1b178dc6f81ee89afa741` (P8 post-hardening) |
| Deployed binary | `bd46b32d3c0b71c4f49cec8aeeb57ade8d4fb2cf132c3993d72c4745b1e04728` — **superseded at 16:22 UTC by `4ed87f92…fa45`; see [§ Post-fix re-verification](#post-fix-re-verification-2026-08-17)** |
| Verified | operator-side **and** from inside the container, byte-identical |

[`deploy-01-binary.txt`](./deploy-01-binary.txt).

### Exposing the host agent's two sockets to the broker

The redeployed broker needs two unix sockets that live on the `spike-spire-agent-state` volume: the
host agent's Broker API endpoint and a Workload API to source its **own** SVID from. The volume was
attached to `spike-broker` read-write, because `connect(2)` on a unix socket requires write
permission on the socket inode:

```
incus config device add spike-broker hostagent disk \
  pool=local source=spike-spire-agent-state path=/hostagent
```

```
local/incus/custom/default_spike-spire-agent-state /hostagent rw,relatime,xattr,posixacl
/hostagent/broker-run/broker.sock  srwxrwx---  root:root  socket
/hostagent/run/api.sock            srwxrwxrwx  root:root  socket
```

**Security consequence, stated plainly.** That volume also holds the P1 DevID material. Broker
container root can now read `/hostagent/devid.priv.blob`, `/hostagent/devid.pub.blob`,
`/hostagent/devid.pem` and `/hostagent/devid.csr`, plus the Incus client credentials under
`/hostagent/incus-creds/`. Enumerated in [`deploy-02-socket-exposure.txt`](./deploy-02-socket-exposure.txt).
This is the same blast-radius class P7 already recorded for `spike-p3-stage`, now extended to the
guest-facing service — the component with the largest attack surface in the system. The TPM-resident
private key is not in those blobs, so this does not by itself yield the host identity; it does hand
an attacker the DevID certificate, the wrapped key objects and a live Incus client key. A production
topology must expose exactly two socket paths, not a volume.

### The broker's own SVID source, and the relay it needed

Making the Workload API socket *reachable* was not sufficient. The SPIRE Workload API endpoint
resolves its caller through `SO_PEERCRED` **in its own PID namespace**; a peer in a sibling
container is unresolvable and the connection is dropped at `accept`. This is the identical failure
P4 and P7 recorded, reproduced here verbatim:

```
WARN Connection failed during accept  error="could not resolve caller information" subsystem_name=endpoints
```

An Incus `proxy` device (`bind=host`, unix→unix) was tried and **rejected**: the socket appeared on
the shared volume, but `forkproxy`'s connect side does not enter the instance PID namespace and the
agent produced the same failure. The device was removed.

What worked is a 60-line byte relay, `p9-wlapi-relay` (`5aa746a2a4406626f3657d9c1d880fc81cacad93ba977367dadd38ddbd817e43`),
launched **inside** the agent container so that it lives in the agent's own PID namespace:

```
incus exec spire-agent -- /spike/bin/p9-wlapi-relay /spike/wlapi-relay.sock /spike/run/api.sock
```

The agent then attested the relay as `unix:uid:0` and issued the broker identity:

```
DEBU Fetched X.509 SVID  count=1 method=FetchX509SVID pid=222 registered=true
     service=WorkloadAPI spiffe_id="spiffe://spike.incus.internal/incus-broker"
```

**Security consequence.** The relay collapses the Workload API's caller attestation to a single
identity: anything that can reach `/spike/wlapi-relay.sock` — i.e. any container mounting that
volume — receives `spiffe://spike.incus.internal/incus-broker`. It is spike scaffolding for one live
run, it is in the teardown inventory, and no production design may ship it. Full transcript:
[`deploy-05-workload-api-relay.txt`](./deploy-05-workload-api-relay.txt).

### Configuration added to `/state/broker.env`

```
INCUS_SPIFFE_BROKER_BROKER_SOCKET=/hostagent/broker-run/broker.sock
INCUS_SPIFFE_BROKER_WORKLOAD_API_SOCKET=/hostagent/wlapi-relay.sock
INCUS_SPIFFE_BROKER_AGENT_SPIFFE_ID=spiffe://spike.incus.internal/spire/agent/tpm_devid/fee6de975fb82fdbd3c7b7ea7e0b752412469fd0
```

`-agent-spiffe-id` is the exact-match branch of the client authorizer, so the broker will complete
the Broker API handshake with the physically attested host node and with nothing else. The
alternative, `-agent-trust-domain`, would accept any member of the trust domain; exactly one of the
two is required and the narrower one was chosen.

Startup line, showing the new fields:

```json
{"msg":"incus-spiffe-broker listening","listen_address":"[::]:8443",
 "redeem_url":"https://10.55.156.44:8443/v1alpha1/redeem",
 "tls_fingerprint":"7cedc92f3e349063cfd060bbe8be4da00dcab4b12b164d765ca926b05147ab93",
 "incus_url":"https://147.135.105.83:8443","project":"spike-spiffe",
 "broker_socket":"/hostagent/broker-run/broker.sock",
 "workload_api_socket":"/hostagent/wlapi-relay.sock",
 "nonce_ttl":"10m0s","max_nonce_ttl":"10m0s","reap_interval":"1m0s",
 "reap_timeout":"30s","reap_grace":"2m0s","request_timeout":"10s"}
```

`ss -ltnp` confirmed `LISTEN *:8443 users:(("incus-spiffe-br",pid=922))`.
[`deploy-04-config-and-startup.txt`](./deploy-04-config-and-startup.txt).

### The exchange registration entry

```
Entry ID   : 70a95e01-b401-4837-a963-c391aa61d8ff
SPIFFE ID  : spiffe://spike.incus.internal/spire-exchange/incus/a955ca30-a0dc-4087-a369-37d53d389c5a
Parent ID  : spiffe://spike.incus.internal/spire/agent/tpm_devid/fee6de975fb82fdbd3c7b7ea7e0b752412469fd0
X509-SVID TTL : 120
Selector   : incus:uuid:a955ca30-a0dc-4087-a369-37d53d389c5a
```

**Why the parent must be the `tpm_devid` node.** A registration entry's parent names the agent that
is allowed to obtain that identity on a workload's behalf. Parenting the exchange entry on the
`tpm_devid` node means the exchange SVID can only ever be minted through the host agent whose node
identity came from the physical TPM, after that agent's `incus-attestor` plugin has independently
re-derived `incus:uuid:<uuid>` from the authoritative Incus instance record. The exchange SVID
therefore **inherits its trustworthiness from the physically attested host**: nothing the guest
possesses can produce it, and nothing the guest claims is believed. The guest's only contribution is
proof of possession of a single-use nonce that the broker itself wrote into that instance's
configuration. Parenting it anywhere else — on the guest node, or on a token-attested node — would
break that inheritance and make the whole chain circular.

`-x509SVIDTTL 120` is deliberate: this is a single-use bootstrap credential, and it should be
useless roughly two minutes after issue. The live leaf confirmed it — `not_before=15:35:55`,
`not_after=15:38:05`, 130 seconds. [`deploy-03-entries.txt`](./deploy-03-entries.txt).

The broker's own SVID entry (`spiffe://spike.incus.internal/incus-broker`, parent = the same
`tpm_devid` node, selector `unix:uid:0`) is in the same transcript. `unix:uid:0` is coarse; see
[§ Findings for the architecture](#findings-for-the-architecture).

## The full chain

Each hop, with the identity that actually carries it. All values are from
[`chain-01-mint.txt`](./chain-01-mint.txt), [`chain-03-guest-bootstrap.txt`](./chain-03-guest-bootstrap.txt)
and [`chain-04-agent-list.txt`](./chain-04-agent-list.txt).

**1 — Operator mints.** `POST /v1alpha1/nonce` with a bearer token, from inside the broker container
where the token already lives. → HTTP `201`, `nonce_id=dd161c4f08ba9658ef1ba267affd7c0f`. The
response carries no nonce, secret or token field; `operator-mint.sh` asserts this and would exit
`20` otherwise. *Identity at this hop: an operator bearer token. No SPIFFE identity is involved yet.*

**2 — Broker writes the binding.** `user.spiffe-bootstrap` set on `spike-guest-a` (267 bytes, fields
`broker_fingerprint`, `broker_url`, `nonce`, `nonce_id`). *Identity: the P5 `spike-bootstrap-writer`
Incus certificate, scoped to project `spike-spiffe`.*

**3 — Guest reads its own key.** `GET /1.0/config/user.spiffe-bootstrap` over `/dev/incus/sock` →
HTTP `200`, `payload_sha256=9ad4b5c0…a334b7`. Only this guest's own socket exposes it; guest B's
socket answered `404` for the whole run. *Identity: guest root inside its own instance — the weakest
link in the chain, and the reason the nonce is single-use and short-lived.*

**4 — Guest pins before it transmits.** The broker leaf was fetched with `openssl s_client` and its
SHA-256 compared with the payload's `broker_fingerprint`: both
`7cedc92f3e349063cfd060bbe8be4da00dcab4b12b164d765ca926b05147ab93`. The SPKI hash
`sha256//VgsjkxXQUOpcDDf3ME0k558xOPa4eQlShWxr+H0l/DA=` was then handed to `curl --pinnedpubkey`, with
`--cacert` chain validation on top. A mismatch would have aborted before the nonce left the guest.

**5 — Redeem.** `POST /v1alpha1/redeem` → HTTP `200`. The broker resolved the binding **server-side**
and returned six selectors it derived itself:

```
incus:uuid:a955ca30-a0dc-4087-a369-37d53d389c5a
incus:generation:c32efc7b-f3d8-4637-9818-f8906c35543a
incus:project:spike-spiffe
incus:type:virtual-machine
incus:name:spike-guest-a
incus:image:9eb18b1a93682960e9e190cd818284ad4bcaf1740be9a435630a3b1dc60acee7
```

**6 — Broker → host agent Broker API.** Over the UDS with mutual SPIFFE TLS: the broker presented
`spiffe://spike.incus.internal/incus-broker` and required the endpoint to be
`spiffe://spike.incus.internal/spire/agent/tpm_devid/fee6de97…`. The request body was an
`IncusInstanceReference{instance_uuid, project}`. *Identity: two SPIFFE IDs, both rooted in the
trust domain, one of them ultimately in the TPM.*

**7 — Host agent re-derives, server matches, exchange SVID issued.** The `incus-attestor` plugin
re-derived `incus:uuid:a955ca30-…` from live Incus state; the server matched entry
`70a95e01-…` and issued:

```
exchange_spiffe_id = spiffe://spike.incus.internal/spire-exchange/incus/a955ca30-a0dc-4087-a369-37d53d389c5a
serial             = 829F56C0096743522E41B6381A1B70B5
validity           = Aug 17 15:35:55 2026 GMT .. Aug 17 15:38:05 2026 GMT
```

**8 — Delivery and local validation.** Chain (1 certificate, leaf first), PKCS#8 key and a 2-cert
bundle were written into a self-mounted tmpfs at mode 0600. The guest checked that the key parses,
that its public part matches the certificate, that the certificate carries a `spiffe://` URI SAN,
and that the SAN is the expected exchange ID — before starting anything.

**9 — `x509pop` node attestation.** The guest agent presented the exchange chain; the server, in
`mode="spiffe"`, verified it against its **own** trust bundle and verified the proof-of-possession
signature, then applied the v1.15.2 defaults — `spiffe_prefix` `/spire-exchange/` trimmed, template
`/{{ .PluginName }}/{{ .SVIDPathTrimmed }}`, `idutil.AgentID` prefixing `/spire/agent`:

```
node_spiffe_id = spiffe://spike.incus.internal/spire/agent/x509pop/incus/a955ca30-a0dc-4087-a369-37d53d389c5a
```

Exactly the mapping [`X509POP_BRIEF.md`](./X509POP_BRIEF.md) predicted from source, with no custom
template and no `spiffe_prefix` set. The server produced two node selectors, and — as the brief
predicted — **no selector derived from the exchange `spiffe:` URI**:

```
x509pop:ca:fingerprint:ef7e6ffe03011a50e1278bdcb4fdd7dc549dedb4
x509pop:serialnumber:829f56c0096743522e41b6381a1b70b5
```

**10 — Two nodes, side by side.** `spire-server agent list`:

```
spiffe://spike.incus.internal/spire/agent/tpm_devid/fee6de975fb82fdbd3c7b7ea7e0b752412469fd0   tpm_devid
spiffe://spike.incus.internal/spire/agent/x509pop/incus/a955ca30-a0dc-4087-a369-37d53d389c5a   x509pop
```

**11 — A serving Workload API.** `spire-agent healthcheck` passed on
`/tmp/spire-agent/public/api.sock`, the SPIRE default path, with no spike-specific client.

**12 — Reclaim.** The exchange material was shredded and its tmpfs unmounted; the harness verified
both before reporting `outcome=PASS`.

## Exchange key handling and its tradeoff

**How it was delivered.** In the `POST /v1alpha1/redeem` **response body**, over TLS whose leaf the
guest had already pinned by fingerprint and SPKI, as `exchange_key_pem` (PKCS#8) beside
`exchange_cert_chain_pem` and `exchange_bundle_pem`. The broker's response type redacts itself in
`String()` and `LogValue()`, so the key has exactly one marshalling site and cannot reach a log.

**How it was held.**

| Property | Observed |
|---|---|
| memory-only | the harness mounted its own tmpfs (`size=1m,mode=0700,nosuid,nodev,noexec`) at `/run/spike-exchange` and asserted `stat -f` reported `tmpfs` **before** transmitting the nonce |
| everything, not just the key | the response body, the chain, the key and the bundle all lived only there, mode 0600 in a 0700 directory; the response file was shredded as soon as the three blobs were extracted |
| single-use | used for exactly one `x509pop` attestation |
| short-lived | issued `15:35:55`, valid until `15:38:05` — 130 seconds — and destroyed the moment attestation succeeded |
| never printed | the harness moved the key from `jq`'s stdout straight into a file; no transcript in this directory contains a `PRIVATE KEY` block |

**The shred, verified rather than asserted** ([`key-01-shred-verification.txt`](./key-01-shred-verification.txt)):

```
--- is /run/spike-exchange still a mount point? ---
not a mount point

--- what is in it? ---
total 0
drwx------  2 root root  40 .
drwxr-xr-x 20 root root 460 ..

spike-exchange mounts in /proc/mounts: 0
0 hits for svid.key / svid.pem / redeem-response* across every mounted filesystem
no file under /var/lib/spire-agent or /run/spike-p9 contains a PRIVATE KEY block
```

What the guest kept is public: `bundle.pem` (2 `CERTIFICATE` blocks) and `agent-data.json`, which
stores the node SVID **certificates** only.

**The tradeoff, stated honestly.** `SPIKE_PLAN.md` P9 step 2 asks this spike to record the design
point rather than declare it solved, and it is not solved. What remains exposed:

- **The key transits the broker process.** The broker receives a full X509-SVID from the host agent
  and serialises the private key into an HTTP response. A compromised broker sees every guest's
  bootstrap key. The broker is also the most exposed component in the system — it is the one
  listening for guests.
- **It transits the guest's memory, and guest root can read it during the window.** tmpfs at mode
  0600 stops a non-root guest process; it stops nothing that is already root, and root is exactly
  who runs the bootstrap. The window is short — under a second in every run here — but it is real.
- **tmpfs pages can be swapped, and a hypervisor-side read of guest RAM sees the key while it is
  live.** Neither is defended against.
- **`shred(1)` on tmpfs is an overwrite plus an unlink, not cryptographic erasure.** Appendix D
  rule 2 forbids claiming otherwise, so this document does not.

What *is* honestly claimed is scope reduction: memory-only, single-use, 130 seconds, never touching
a persistent guest filesystem — so the key cannot be recovered from a disk image, a volume, or a
snapshot. The reboot evidence supports that directly: after `incus restart`, `/run/spike-exchange`
was **gone**, and the only SPIRE material on disk was public.

**What the alternatives would cost.**

| Alternative | What it buys | What it costs |
|---|---|---|
| Guest generates the keypair, broker returns only a certificate (CSR-style) | the private key never leaves the guest and never enters the broker — this removes the two largest exposures at once | a CSR round trip, and the Broker API would have to accept a caller-supplied public key; `spiffe.broker` `v1alpha1` as used here mints an SVID and returns its key, so this is an upstream API change, not a configuration one |
| Deliver into guest RAM through a channel guest root cannot read (vsock to a per-instance endpoint, or a TPM/vTPM-sealed blob) | narrows the reader from "guest root" to "the process that needs it" | a vTPM per guest, or a new device model; both are topology the spike has not tested, and `[INFERENCE]` neither removes the broker from the path |
| Shorten the TTL further (30 s) | shrinks the window proportionally | attestation must complete inside it; a slow boot turns a security margin into an outage, and the operator gains a class of flaky failures |
| Skip the exchange credential: attest the guest node directly from the host agent | no bootstrap key at all | there is no SPIRE node attestor that works this way; it would mean the host agent issuing node identities, i.e. a second control plane |

The CSR-style variant is the one worth costing properly before production. Recorded as go/no-go
input, consistent with risk **R7**.

## In-guest Workload API

A registration entry was created for an ordinary in-guest workload, parented to the **new guest
node** and keyed on a guest `unix` selector — nothing Incus-specific runs inside the guest:

```
SPIFFE ID     : spiffe://spike.incus.internal/guest/demo
Parent ID     : spiffe://spike.incus.internal/spire/agent/x509pop/incus/a955ca30-a0dc-4087-a369-37d53d389c5a
X509-SVID TTL : 120
Selector      : unix:uid:0
```

[`workload-01-entry.txt`](./workload-01-entry.txt). The short TTL was chosen so the rotation at half
life falls inside the run.

The first fetch, 28 seconds after entry creation, returned `PermissionDenied: no identity issued` —
the entry had not yet propagated to the guest agent's cache. Retried after the sync interval, and
recorded here rather than hidden, because "wait for the sync interval" is the correct operational
answer and a P10 case may hit it again.

```
RESULT check=issuance outcome=PASS spiffe_id=spiffe://spike.incus.internal/guest/demo
       serial=CB2E3624BC367E536816DAAD97E218C9
       not_before=Aug 17 15:38:12 2026 GMT not_after=Aug 17 15:40:22 2026 GMT

RESULT check=rotation outcome=PASS mode=poll
       first_serial=CB2E3624BC367E536816DAAD97E218C9
       second_serial=1BA4352E183EF8856537047E0205CF25
       waited_seconds=30 spiffe_id=spiffe://spike.incus.internal/guest/demo

RESULT check=workload outcome=PASS ... rotation=observed material=shredded-and-unmounted
```

The second SVID's window is `15:39:06 .. 15:41:16`: a new certificate, a new serial, the **same**
SPIFFE ID. That is the phase's acceptance criterion met with an unmodified `spire-agent api fetch
x509` client against the SPIRE-default socket path, and it is also the basis for P10's
stale-credential cases — a rotating agent holds a live relationship with the server, not a one-shot
credential. [`workload-02-fetch-and-rotation.txt`](./workload-02-fetch-and-rotation.txt).

## Restart and reboot

`SPIKE_PLAN.md` P9 step 4 asks for the intended story to be **defined** and then verified. It was
defined before the run, by `AGENT_KEY_MANAGER=memory`, and both halves were then tested.

### (a) Agent process restart — [`restart-01-agent-process.txt`](./restart-01-agent-process.txt)

Killed the agent and restarted it with byte-identical configuration:

```
level=error msg="Failed to configure plugin"
  error="rpc error: code = InvalidArgument desc = unable to load keypair:
         open /run/spike-exchange/svid.pem: no such file or directory"
  plugin_name=x509pop plugin_type=NodeAttestor
level=error msg="Agent crashed"
```

The agent did **not** return to an attested state and no Workload API served
(`Agent is unhealthy`). It needed a fresh nonce. On disk it had only `bundle.pem` and
`agent-data.json` — public material; the node key was in memory and died with the process.

Recovery: one fresh nonce and one re-run of the harness restored it, with the **same** node SPIFFE
ID and a **new** serial selector (`x509pop:serialnumber:7dc8d002…`), because the new exchange
certificate has a new serial.

### (b) Guest VM reboot — [`restart-02-guest-reboot.txt`](./restart-02-guest-reboot.txt)

```
spire-agent process:                              none
/run/spike-p9 (rendered config + log):            GONE
/run/spike-exchange (the tmpfs that held the key): GONE
/var/lib/spire-agent (persistent data_dir):       agent-data.json  bundle.pem
private keys on disk:                             none
```

`volatile.uuid.generation` was **unchanged** (`c32efc7b-…`) across a plain `incus restart`: a reboot
alone does not invalidate an outstanding nonce, which matters for the P10 snapshot/restore cases
where it does move. The server still listed the guest node — an attested node record outlives the
guest agent — but nothing in the guest could use it. Recovery again took one fresh nonce and one
harness run, after which the in-guest workload was issued
`spiffe://spike.incus.internal/guest/demo` again.

### Which story the spike actually demonstrates

**Fresh-credential-per-boot.** Explicitly, and by choice:

- `AGENT_KEY_MANAGER=memory` keeps the node-SVID key in memory, so an agent restart or a guest
  reboot loses it and forces re-attestation;
- re-attestation needs the `x509pop` credential, which was shredded after its single use and whose
  leaf had a 130-second life anyway — so a reboot **cannot** reuse it even in principle;
- therefore recovery is one operator-minted nonce plus one bootstrap, per boot. Observed twice.

**Agent-SVID persistence was not demonstrated** and is not claimed. `AGENT_KEY_MANAGER=disk` would
render the other half: the node key persists in `data_dir`, the agent resumes its identity across a
restart without re-attesting, and a fresh exchange credential is needed only when the node SVID
expires. Its cost is a long-lived identity key on the guest filesystem — carried away by any
snapshot, disk image or stolen volume — and a node identity no longer tied to a live Incus instance
record, which is the property the whole architecture rests on.

**What a production design has to choose.** Fresh-credential-per-boot is the security-correct
default and it makes every boot depend on the operator mint path being available; that is an
availability requirement on the broker and the host agent, and it needs the mint step automated
(the reboot here was recovered by an operator command, which does not scale). Persistence is
operationally cheaper and weakens the binding. The middle option worth costing is
fresh-credential-per-boot with the mint step driven by the instance lifecycle — mint on
`instance-started`, so a rebooting guest finds a valid nonce waiting. That is not implemented and
not tested here.

## Negative checks

### N1 — Nonce reuse ([`negative-01-nonce-reuse.txt`](./negative-01-nonce-reuse.txt))

The payload was preserved in a mode-0600 file inside the guest *before* redemption (never printed),
the bootstrap was run normally to a `PASS`, and then the same nonce was replayed from the preserved
copy into a separate tmpfs and data directory:

```
redeem: HTTP 409
verdict: REJECTED 409 conflict
RESULT phase=p9-bootstrap outcome=ERROR reason=redeem_rejected status=409 broker_reason=conflict
exit 11
```

Broker side: `"reason":"nonce: consume nonce 32da…: nonce: nonce already used"`. The preserved
payload was shredded afterwards.

### N2 — Guest B cannot read A's key ([`negative-02-guest-b.txt`](./negative-02-guest-b.txt))

With no nonce minted for it, B's own `/dev/incus/sock` answered `404`; the harness exited `3` with
`reason=bootstrap_key_absent` and never transmitted anything. Delivery is per-instance.

### N3 — Guest B with its own nonce gets only B, and never a node

B redeemed a nonce minted for **B**. The broker ignored everything B might claim and resolved B's
own UUID, for which no exchange registration entry exists. The Broker API therefore returned no
SVID:

```
redeem: HTTP 503
RESULT ... reason=redeem_rejected status=503 broker_reason=unavailable   (exit 13)
```

```json
{"level":"ERROR","msg":"nonce consumed but no exchange SVID was issued","operation":"redeem",
 "outcome":"burned","instance_uuid":"a4fec3ea-d4aa-4e6c-94c6-8295cee62338",
 "failure_class":"broker_no_svid","http_status":503,"code":"unavailable",
 "reason":"broker delivered no X.509-SVID: response carried an empty SVID list"}
```

`spire-server agent list` continued to show exactly two nodes; B never obtained one. This is also
the natural **Broker-side failure** the phase asks to classify: it occurred **after** nonce
consumption, mapped to the **503 / retryable** class, and **burned the nonce** — `bootstrap key
cleared` was logged and B's `user.spiffe-bootstrap` was empty afterwards. The guest must obtain a
fresh nonce; that is the documented contract, observed rather than reasoned about.

### The case that is still open, and is now worse

P8 measurement **M1** stands unchanged: an **unused, leaked** A nonce is a bearer credential, and a
holder can redeem it as A. P9 does not fix that and it raises the stakes — in P8 the reward was
binding metadata, in P9 it is a working `x509pop` credential for A's node identity, valid for about
two minutes. It was not re-run here because P8 already measured it and it is P10 case 5; it is
restated so that no reader concludes P9 closed it. The mitigations that exist today are the ones
already recorded: a 10-minute nonce TTL, single use, generation invalidation, and the reaper that
withdraws an unredeemed key.

## Findings for the architecture

1. **The broker cannot source its own SVID from the host agent's Workload API across a container
   boundary.** This is not new — P4 and P7 recorded the same `could not resolve caller information`
   — but P9 is the first phase where the *product* code depends on it: `-workload-api-socket` is a
   required flag. Three real options: run the broker inside the host agent's PID namespace; give the
   broker a node identity of its own; or have the Broker API hand back a broker credential. An Incus
   `proxy` device is **not** an option — it was tried and it fails the same way. The spike relay is
   a measurement device, not a design.
2. **`unix:uid:0` is the only selector the host agent can produce for a cross-container caller**, and
   with the relay it is the only selector it can produce at all. Any tightening — `unix:path`,
   `unix:sha256` — requires the caller to be resolvable in the agent's PID namespace, which is the
   same finding restated. The broker's identity is currently protected by filesystem permissions on
   a volume, not by attestation.
3. **The exchange credential's exposure is the phase's real unsolved problem**, and the CSR-style
   variant is the alternative worth costing. See [§ Exchange key handling](#exchange-key-handling-and-its-tradeoff).
4. **The `x509pop` node identity is stable across re-attestation; only the serial selector moves.**
   Three separate bootstraps produced the same node SPIFFE ID and three different
   `x509pop:serialnumber:` selectors. A registration entry parented on the node ID therefore
   survives re-bootstrap, which is what makes the guest workload entry durable. An entry keyed on
   the serial selector would not.
5. **A short exchange TTL and node re-attestation interact.** The node SVID is issued for an hour
   while the exchange credential dies in two minutes and is destroyed immediately. SPIRE sets
   `CanReattest: true` and re-attestation reloads the `x509pop` credential paths — so an agent that
   is forced to re-attest mid-life will find nothing there. Not observed in this window (no
   re-attestation was triggered); flagged from source in
   [`X509POP_BRIEF.md`](./X509POP_BRIEF.md) and worth a P10 case. `[INFERENCE]`
6. **The redeem response's field names are not in the harness's accepted list.** **CORRECTED: fixed at `3f5b7f6`. The harness now reads `exchange_cert_chain_pem` / `exchange_key_pem` / `exchange_bundle_pem` — the broker's own names — FIRST, and the overrides are needed only for an out-of-tree broker; proven live in [`postfix-02b-clean-run.txt`](./postfix-02b-clean-run.txt).** As originally written: cosmetic, cost one
   nonce, fixed with the documented `CHAIN_JQ`/`KEY_JQ`/`BUNDLE_JQ` overrides. Worth noting only
   because the harness's failure was exemplary: it named the fields it looked for, withheld a body
   that may contain a key, shredded the tmpfs and exited `4`.
7. **Entry propagation is not instantaneous.** A workload fetch 28 seconds after entry creation
   returned `PermissionDenied`. Operationally trivial, but a P10 case that creates an entry and
   immediately asserts on it will be flaky.

## Secret handling

Appendix D now covers a private key as well as a nonce value, and P9 is the first phase where a real
private key exists to leak. Four things kept it out of this directory.

1. **The broker cannot log it.** `redeemResponse` implements `String()` and `LogValue()`, both of
   which replace the key with a redaction constant; the key has exactly one marshalling site.
2. **The harness never prints it and never captures a response body.** The key moves from `jq`'s
   stdout straight into a mode-0600 file on tmpfs; foreign output is filtered for PEM private-key
   headers and long bare-base64 lines. Every transcript shows `nonce=<redacted, present>` and
   `key=<shredded, never printed>`.
3. **No transcript here was produced by `curl -v`/`-i`, a proxy, or a paste.** The one command that
   would have exposed a raw body — reading the redeem response — does not exist in this run.
4. **An executed scan**, [`secret-scan.txt`](./secret-scan.txt): the Appendix D rule 4 mechanical
   checks (PEM `PRIVATE KEY` blocks, base64 runs longer than 64 characters, the strings `recovery`
   and `nonce=`), a full attribution of every 64-hex token in the directory, and **two live positive
   controls** — a freshly minted nonce secret and a freshly issued exchange **private key**, each
   used as a `grep -F -f` needle **file** so neither reached `argv`, each proven to match a planted
   copy and to match nothing in the evidence.

One deliberate omission is worth naming: the host security state was read from
`/os/1.0/system/security`, whose response also carries `drive_recovery_keys`, `pool_recovery_keys`
and `config.encryption_recovery_keys`. Only the five non-secret fields were extracted into
[`cleanup-final-state.txt`](./cleanup-final-state.txt); the recovery-key fields were never written
to any file.

## Commands exercised

```sh
# 1. redeploy
incus exec spike-broker -- systemctl stop incus-spiffe-broker.service
incus file push /tmp/incus-spiffe-broker-linux spike-broker/usr/local/bin/incus-spiffe-broker --mode 0755
incus exec spike-broker -- sha256sum /usr/local/bin/incus-spiffe-broker
incus config device add spike-broker hostagent disk pool=local source=spike-spire-agent-state path=/hostagent

# 2. the relay the broker's own SVID needed
incus file push /tmp/p9-wlapi-relay spike-p3-stage/state/bin/p9-wlapi-relay --mode 0755
incus exec spire-agent -- /spike/bin/p9-wlapi-relay /spike/wlapi-relay.sock /spike/run/api.sock

# 3. configuration and restart
#   INCUS_SPIFFE_BROKER_BROKER_SOCKET / _WORKLOAD_API_SOCKET / _AGENT_SPIFFE_ID appended to /state/broker.env
incus exec spike-broker -- systemctl restart incus-spiffe-broker.service

# 4. registration entries
spire-server entry create -parentID .../spire/agent/tpm_devid/fee6de97... \
  -spiffeID .../incus-broker -selector unix:uid:0 -x509SVIDTTL 3600
spire-server entry create -parentID .../spire/agent/tpm_devid/fee6de97... \
  -spiffeID .../spire-exchange/incus/a955ca30-... \
  -selector incus:uuid:a955ca30-... -x509SVIDTTL 120
spire-server entry create -parentID .../spire/agent/x509pop/incus/a955ca30-... \
  -spiffeID .../guest/demo -selector unix:uid:0 -x509SVIDTTL 120

# 5. the chain
incus exec spike-broker -- env BROKER_URL=https://10.55.156.44:8443 \
  BROKER_CACERT=/state/tls/spike-root-ca.pem MINT_AUTH_TOKEN_FILE=/state/auth/mint-token \
  /root/p8/operator-mint.sh a955ca30-a0dc-4087-a369-37d53d389c5a spike-spiffe
incus exec spike-guest-a --project spike-spiffe -- env \
  SPIRE_SERVER_ADDRESS=10.55.156.67 SPIRE_SERVER_PORT=8081 TRUST_DOMAIN=spike.incus.internal \
  BROKER_CACERT=/root/p9/broker-ca.pem \
  CHAIN_JQ=.exchange_cert_chain_pem KEY_JQ=.exchange_key_pem BUNDLE_JQ=.exchange_bundle_pem \
  /root/p9/guest-agent-bootstrap.sh
incus exec spike-guest-a --project spike-spiffe -- \
  /root/p9/guest-workload-check.sh spiffe://spike.incus.internal/guest/demo

# 6. restart and reboot
incus exec spike-guest-a --project spike-spiffe -- sh -c 'kill $(cat /run/spike-p9/agent.pid)'
incus exec spike-guest-a --project spike-spiffe -- sh -c 'setsid spire-agent run -config /run/spike-p9/agent.conf ...'
incus restart spike-guest-a --project spike-spiffe

# 7. negatives
#   replay:  PAYLOAD_FILE=/run/p9-payload.json ... guest-agent-bootstrap.sh   -> 409, exit 11
#   guest B, no nonce:                            guest-agent-bootstrap.sh   -> 404, exit 3
#   guest B, own nonce:                           guest-agent-bootstrap.sh   -> 503, exit 13, nonce burned

# 8. close-out
spire-server entry delete -entryID 329f6690-12fa-4e16-a1d0-32db8f50cd11
incus query /os/1.0/system/security   # five non-secret fields only
```

## Cleanup and final state

[`cleanup-final-state.txt`](./cleanup-final-state.txt).

- The test workload entry `spiffe://spike.incus.internal/guest/demo` was **deleted**.
- The exchange entry (`70a95e01-…`) and the broker-SVID entry (`718f0f2e-…`) were **retained**:
  they are chain infrastructure, not test artifacts, and every P10 case needs them. Both are in the
  teardown inventory below. Recorded as a decision, not an oversight.
- **The guest node is left attested**, deliberately. P10 is the adversarial matrix and it starts
  from a working chain; re-bootstrapping it would only consume another nonce.
- `user.spiffe-bootstrap` is `<unset>` on **all eight** instances across both projects, verified by
  enumeration rather than assumption.
- `spike-guest-a` still runs its agent (`Agent is healthy`) on `/tmp/spire-agent/public/api.sock`.
- The host agent is attested and healthy: `tpm_devid` node present, `/live` and `/ready` both `200`.
- The broker is `active` and listening on `*:8443`. Both guests and every helper container are
  `RUNNING`; nothing was deleted.
- Host untouched:
  `{"secure_boot_enabled":true,"encrypted_volumes":[{"state":"unlocked (TPM)","volume":"root"},{"state":"unlocked (TPM)","volume":"swap"}],"tpm_status":"ok","system_state_status":"system state is fully trusted","system_state_is_trusted":true}`,
  and `uptime_seconds: 61683` — the host has not rebooted at any point in this spike. No TPM command
  was run, no `incus admin os` mutation, no change to the code worktree, no repository gate, no Git
  command.

## Post-fix re-verification (2026-08-17)

Second live run, 16:22–16:37 UTC, same host. Everything above this heading is the original P9
run and is left as it was written. This section is additive: it records a run against a **fixed**
broker and a **fixed** harness, and corrects — in place, with an explicit note at each site — the
claims the fix made wrong. Nothing was deleted.

### Why it happened

Two reasons, both recorded above.

1. An independent security review of the P9 broker and harness (commit `609885e`) found
   **eight defects** — see [`SECURITY_FINDINGS.md`](./SECURITY_FINDINGS.md). Six had a
   phase-local code or harness disposition and have been fixed at commit `3f5b7f6`.
2. The original run could not claim a clean chain. Finding **F2** below cost a nonce and then
   required three hand-passed `jq` overrides on the bootstrap command line. A phase whose
   headline is "the guest chain works" cannot rest on a manual workaround.

The **two high-severity findings were deliberately NOT fixed in code** and remain architecture
go/no-go input under `SPIKE_PLAN.md:309-311`:

- **SEC-009 escalated (High)** — the bearer nonce now buys the bound instance's exchange
  chain, unencrypted PKCS#8 key and bundle, which is enough to become the derived guest node.
  Carried as an architecture decision: the carrier and proof protocol need a production
  decision, not a patch. This re-verification does not close it and does not claim to.
- **Broker blast radius (High)** — one network-facing process holds Incus credentials, the
  host agent's Broker socket and a Workload API SVID authorized to request identities.
  Carried as an architecture decision: split the authorities and the socket exposure before
  production. The redeploy below reused the existing socket exposure unchanged, so the blast
  radius recorded in [§ Deployment](#deployment) is exactly as it was.

Both are stated in full in [`SECURITY_FINDINGS.md`](./SECURITY_FINDINGS.md), which this
section does not restate and does not supersede.

### The redeployed binary

| Item | Value |
|---|---|
| Binary replaced | `bd46b32d3c0b71c4f49cec8aeeb57ade8d4fb2cf132c3993d72c4745b1e04728` (the original P9 run) |
| Deployed binary | `4ed87f92ca113334c2e2e60127ae00131a47273ac476dd1d2f05b8f2e463fa45` |
| Verified | operator-side **and** by `sha256sum` **inside the container**, byte-identical |
| Commit | `3f5b7f6` |

Socket exposure, TLS material, the operator mint token and every `INCUS_SPIFFE_BROKER_*`
setting were left exactly as they were; nothing was re-provisioned.
[`postfix-01-redeploy.txt`](./postfix-01-redeploy.txt).

**Correction to a claim made above.** [§ Cleanup and final state](#cleanup-and-final-state)
lists "`/live` and `/ready` both `200`" under the broker. Those two endpoints belong to the
**host SPIRE agent**, not to the broker; the broker exposes neither and answers `404` on both.
The original transcript was correct — it labelled them "host agent health" — but the summary
line reads as though the broker served them. Broker liveness is evidenced by its `LISTEN`
line and by live mint/redeem traffic.

### The clean run — the headline of this re-verification

The chain was rebuilt **from nothing**. The guest node the original run left attested was
removed with `spire-server agent evict` before anything else happened, and the guest's
`data_dir` was deleted, so the server listed exactly one node — the physically attested
`tpm_devid` host — and the guest held no SPIRE material at all.
[`postfix-02a-teardown.txt`](./postfix-02a-teardown.txt).

**`evict`, not `ban`, and why.** `ban` blacklists the agent SPIFFE ID and refuses all future
attestation, which would have made the re-run impossible. `evict` deletes the attested node
record, so the next attestation is a **first** attestation rather than a re-attestation.
The node identity that came back is byte-identical, and that is a property of the derivation,
not a leftover: `x509pop` derives the node ID from the exchange SVID's SPIFFE ID, which the
broker derives from the **instance UUID**. `a955ca30-…` belongs to the Incus instance, not to
any credential. A stable ID here is therefore evidence that the mapping is deterministic —
finding 4 in [§ Findings for the architecture](#findings-for-the-architecture), now
demonstrated across an eviction rather than only across re-bootstraps.

Then one nonce, minted through the authenticated operator endpoint, and one command:

```sh
incus exec spike-guest-a --project spike-spiffe -- env \
  SPIRE_SERVER_ADDRESS=10.55.156.67 SPIRE_SERVER_PORT=8081 \
  TRUST_DOMAIN=spike.incus.internal BROKER_CACERT=/root/p9/broker-ca.pem \
  /root/p9/guest-agent-bootstrap.sh
```

**What is not on that command line is the point:** no `CHAIN_JQ`, no `KEY_JQ`, no
`BUNDLE_JQ`, no hand-editing of the script, no manual field extraction. It exited `0` on the
first attempt, consuming exactly one nonce. The harness said so itself:

```
extraction: primary fields exchange_cert_chain_pem, exchange_key_pem, exchange_bundle_pem (the broker's own names);
extraction: compatibility spellings are tried only after them
```

and the `RESULT` line, in full:

```
RESULT phase=p9-bootstrap outcome=PASS nonce_id=804ea6d00fcfb1528f90bf6ecabd9ca2
  instance_uuid=a955ca30-a0dc-4087-a369-37d53d389c5a
  exchange_spiffe_id=spiffe://spike.incus.internal/spire-exchange/incus/a955ca30-a0dc-4087-a369-37d53d389c5a
  exchange_not_after=Aug 17 16:25:46 2026 GMT
  node_spiffe_id=spiffe://spike.incus.internal/spire/agent/x509pop/incus/a955ca30-a0dc-4087-a369-37d53d389c5a
  key_manager=memory workload_api=/tmp/spire-agent/public/api.sock
  exchange_retention=shred exchange_material=shredded-and-unmounted
```

Four things that transcript establishes, each of which the original run could not:

1. **The canonical field names were consumed.** The harness tries
   `exchange_cert_chain_pem` / `exchange_key_pem` / `exchange_bundle_pem` — the broker's own
   response-type names — *first*, and the compatibility spellings only after. F2 is closed.
2. **The exchange SPIFFE ID matched** `…/spire-exchange/incus/a955ca30-a0dc-4087-a369-37d53d389c5a`,
   checked against the **certificate**, which is authoritative, not merely against the JSON field.
3. **The guest agent attested**, producing the v1.15.2 default node ID that
   [`X509POP_BRIEF.md`](./X509POP_BRIEF.md) predicted from source.
4. **The server lists the guest node again**, from a state where it listed only the host —
   with a new `x509pop:serialnumber:19ffc449…` selector, because it is a new exchange
   certificate, and the same `x509pop:ca:fingerprint:ef7e6ffe…`.

[`postfix-02b-clean-run.txt`](./postfix-02b-clean-run.txt).

### The burned-nonce code, proven deliberately

F3 below recorded `outcome=burned` as something that *happened* to guest B. The fixed broker
names the condition to the caller, so this run forced it on purpose and then proved the nonce
was really spent.

**The lever.** The exchange registration entry was deleted for the duration of one redemption.
The broker's Broker API call then reached a healthy host agent, the host agent re-derived
`incus:uuid:a955ca30-…`, the server matched nothing, and returned an empty SVID list. This was
chosen over pointing the broker at a bogus socket path because it leaves the binary, the
configuration, the TLS identity and the Broker API socket untouched — one server-side record
moves and is restored.

| | Status | Body, verbatim |
|---|---|---|
| Redemption that burned the nonce | `503` | `{"error":"nonce_consumed_without_svid"}` |
| Replay of that same nonce, working config restored | `409` | `{"error":"conflict"}` |

The broker log line for the burn:

```json
{"level":"ERROR","msg":"nonce consumed but no exchange SVID was issued","operation":"redeem",
 "outcome":"burned","nonce_id":"dbb0096ee125b97b40168e7981b3b3ff",
 "instance_uuid":"a955ca30-a0dc-4087-a369-37d53d389c5a","project":"spike-spiffe",
 "failure_class":"broker_no_svid","http_status":503,"code":"nonce_consumed_without_svid",
 "reason":"broker delivered no X.509-SVID: response carried an empty SVID list"}
```

**The contrast is the whole point.** Two different codes for two different facts. The `503`
says "your nonce is spent and you got nothing for it, go get a fresh one", which is
actionable. The `409` is the ordinary single-use conflict and is **unchanged** from the
pre-fix broker — so the burn code does not leak into the replay path, and a caller cannot use
the replay response to probe whether a nonce was burned or merely reused.

**Visible change against the old binary.** The same condition on the pre-fix broker logged
`"code":"unavailable"` — see [§ N3](#negative-checks) and
[`negative-02-guest-b.txt`](./negative-02-guest-b.txt). It now logs
`"code":"nonce_consumed_without_svid"`, matching the body. The HTTP status class is preserved:
`503` for this dependency failure, not a new status.

The entry was restored and the clean path re-verified end to end (Run A of the retention
comparison below is that re-verification, and it passed).
[`postfix-04-burn.txt`](./postfix-04-burn.txt).

### Both Workload API verdicts

[§ In-guest Workload API](#in-guest-workload-api) above proved issuance for **uid 0 only**.
The review's point is that "an in-guest **application** obtains its SVID from a standard local
Workload API" is not established by a root fetch: root can traverse any directory and is the
same uid that created the socket. So a second entry was registered for an unprivileged uid,
parented on the guest node, and both fetches were run.

```
spire-server entry create -parentID .../spire/agent/x509pop/incus/a955ca30-... \
  -spiffeID .../guest/demo     -selector unix:uid:0   -x509SVIDTTL 120
spire-server entry create -parentID .../spire/agent/x509pop/incus/a955ca30-... \
  -spiffeID .../guest/demo-app -selector unix:uid:989 -x509SVIDTTL 120
```

```
RESULT check=issuance         outcome=PASS caller=root uid=0     spiffe_id=.../guest/demo
                              serial=6E7977601C28A503CEF5D00AD555FA90
RESULT check=issuance-nonroot outcome=PASS user=spike-workload uid=989 spiffe_id=.../guest/demo-app
                              serial=9E51DBA10B9199A1668ACA294451F80F
RESULT check=workload         outcome=PASS ... nonroot=PASS nonroot_uid=989
exit 0
```

The two callers received **different SPIFFE IDs from the same socket**, because the agent
attested each caller's uid independently. That is the Workload API doing real caller
attestation inside the guest, not a shared credential handed to whoever connects. Exit `24`
is the code reserved for "root served, non-root not"; it was not reached.

**A precision note, because the mechanism matters.** `guest-agent-bootstrap.sh` creates any
*missing* socket-directory component mode `0755`. Here `/tmp/spire-agent` and
`/tmp/spire-agent/public` already existed at mode `0700` from the original run, so the harness
did not recreate them — it added `o+x` to each, giving `0701`, and logged both actions. `0701`
is the tighter outcome and is sufficient: traversal needs only `x`. SPIRE itself serves the
socket `0777`, so the directory was the only barrier.
[`postfix-03-workload.txt`](./postfix-03-workload.txt).

### Retention: the cost of fresh-credential-per-boot, measured

[§ Restart and reboot](#restart-and-reboot) argued that the spike demonstrates
fresh-credential-per-boot **by choice**. `EXCHANGE_RETENTION` makes that choice explicit and
reversible, so both sides were run on the same guest, minutes apart.

| | `shred` (default) | `keep` |
|---|---|---|
| exchange key after use | overwritten, tmpfs unmounted | **live** in `/run/spike-exchange` |
| `RESULT exchange_material` | `shredded-and-unmounted` | `kept-by-policy` |
| agent survives a process restart | **NO** — `unable to load keypair` | **YES** — re-attests, same node ID |
| Workload API after restart | not serving (`Agent is unhealthy`) | serving; both SVIDs re-issued |
| recovery cost | one operator-minted nonce | none |
| who can steal the credential | nobody, ~1 second after issue | any guest root, until it expires |
| operator warning printed | no | yes, boxed, on stderr |

Under `shred` the restart failed exactly as documented:

```
level=error msg="Failed to configure plugin" plugin_name=x509pop plugin_type=NodeAttestor
            error="rpc error: code = InvalidArgument desc = unable to load keypair:
                   open /run/spike-exchange/svid.pem: no such file or directory"
level=error msg="Agent crashed"
```

Under `keep` the same restart re-attested:

```
level=info msg="SVID is not found. Starting node attestation" subsystem_name=attestor
level=info msg="Node attestation was successful" reattestable=true
           spiffe_id="spiffe://spike.incus.internal/spire/agent/x509pop/incus/a955ca30-..."
level=info msg="Creating X509-SVID" spiffe_id=".../guest/demo"
level=info msg="Creating X509-SVID" spiffe_id=".../guest/demo-app"
```

`reattestable=true` confirms the server marks `x509pop` nodes re-attestable, so the **only**
thing that stopped the `shred` restart was the absence of the credential files — which
settles finding 5 in [§ Findings for the architecture](#findings-for-the-architecture)
empirically. That finding was marked `[INFERENCE]` because no re-attestation had been
watched; one has now been watched, on both sides.

**The `keep` warning is loud, and accurate.** It names the node identity a guest-root thief
would obtain and the instant it expires, states that the credential is no longer single-use
or short-lived, and reminds the reader that tmpfs pages can be swapped so "memory-only" is
not a guarantee. It also prints the exact destruction command, which was then used.

**Stated plainly:** `shred` is the security-correct default and its price is the Run A
failure — every boot and every agent restart is an outage until an operator mints a nonce.
`keep` removes that outage and replaces it with a live private key in guest RAM that any
guest-root compromise can lift and replay as the node identity. Neither is free. The middle
option this document already named — mint driven by the instance lifecycle, so a rebooting
guest finds a valid nonce waiting — is still not implemented and still not tested.

The guest was left in the `shred` state.
[`postfix-05-retention.txt`](./postfix-05-retention.txt).

### Secret handling, re-scanned — and a defect found in the scan itself

The full Appendix D scan was re-run over the **whole** directory, now 29 files, with two
live positive controls: a real nonce secret read straight from `user.spiffe-bootstrap` into a
mode-0600 needle **file** (never printed, never in `argv`, `grep -f`), and a real exchange
**private key** obtained by running a bootstrap with `EXCHANGE_RETENTION=keep`.

Result: **clean** — 0 PEM private-key blocks, 0 recovery-key values, 0 bare `nonce=<64 hex>`,
0 unattributed 64-hex tokens, 0 hits for either live secret. Both controls matched their
planted copies, so the scan is proven able to fail.

**Finding S1 — the original run's base64 check could not have caught a pasted PEM key.**
[`secret-scan.txt`](./secret-scan.txt) used `^[A-Za-z0-9+/]{65,}={0,2}$` and reported 0 hits.
But PEM wraps base64 at **exactly 64 columns**, so a wrapped key body never reaches 65
characters — measured on the live key, its body lines are 64, 64 and 56. That check passed
for the wrong reason; `CHECK 1`, the PEM header, did the real work. Corrected to `{64,}` it
fires on the real key and still returns **0** on every file here. The original pattern was
not useless — it catches the *unwrapped* form, which is how a key would appear if a redeem
response body were pasted, and that is the leak it was aimed at — but it was narrower than
the prose above claimed. **S1 is a defect in the scan, not a leak in the evidence:** no key
and no nonce is present under either pattern.

All control material — needle files, planted copies, the pulled key — was overwritten and
removed, and the guest's retained credential destroyed with the command the warning printed.
[`postfix-07-secret-scan.txt`](./postfix-07-secret-scan.txt).

### Close-out state

Both entries added for the Workload API proof (`/guest/demo`, `/guest/demo-app`) were
**deleted** — they are test workloads, and P10 needs neither. What remains is exactly the two
chain-infrastructure entries:

```
718f0f2e-1430-4ea8-9179-ae7223724f6b  spiffe://spike.incus.internal/incus-broker
655e2c68-0a1f-423b-8cbd-bc6c7fc060c0  spiffe://spike.incus.internal/spire-exchange/incus/a955ca30-...
```

**Note for the teardown inventory:** the exchange entry's ID has **changed**. It was
`70a95e01-b401-4837-a963-c391aa61d8ff`; deleting and recreating it for the burned-nonce proof
produced `655e2c68-0a1f-423b-8cbd-bc6c7fc060c0`. Same SPIFFE ID, same parent, same selector,
same TTL — only the record ID moved. The ID recorded under
[§ Teardown inventory additions](#teardown-inventory-additions) is stale and is superseded here.

Final state, verified after all work including the secret-scan controls:

- Two attested nodes: the `tpm_devid` host and `…/x509pop/incus/a955ca30-…`.
- `spike-guest-a` runs its agent, `Agent is healthy`, Workload API serving, 0 `spike-exchange` mounts.
- `user.spiffe-bootstrap` is `<unset>` on **all eight** instances across both projects, enumerated.
- Broker `active`, listening on `*:8443`, still `4ed87f92…fa45`.
- Host agent attested; `/live` and `/ready` both `200`.
- Host untouched:
  `{"secure_boot_enabled":true,"encrypted_volumes":[{"state":"unlocked (TPM)","volume":"root"},{"state":"unlocked (TPM)","volume":"swap"}],"tpm_status":"ok","system_state_status":"system state is fully trusted","system_state_is_trusted":true}`.
- No TPM command, no `incus admin os` mutation, no host reboot, no change to the code
  worktree, no repository gate, no Git command. Nothing was deleted; both guests persist into P10.

[`postfix-06-final.txt`](./postfix-06-final.txt).

### Transcripts added by this re-verification

| File | What it holds |
|---|---|
| [`postfix-01-redeploy.txt`](./postfix-01-redeploy.txt) | stop, push, in-container sha256 match, unchanged config, restart, startup log |
| [`postfix-02a-teardown.txt`](./postfix-02a-teardown.txt) | agent stopped, `data_dir` removed, node evicted, one node left |
| [`postfix-02b-clean-run.txt`](./postfix-02b-clean-run.txt) | **the clean run**: mint, bootstrap with no overrides, exit 0, node rebuilt |
| [`postfix-03-workload.txt`](./postfix-03-workload.txt) | both entries, both verdicts, socket-permission detail |
| [`postfix-04-burn.txt`](./postfix-04-burn.txt) | forced burn, verbatim `503` body, log line, `409` replay contrast, restore |
| [`postfix-05-retention.txt`](./postfix-05-retention.txt) | `shred` vs `keep` side by side, both restart outcomes, boxed warning |
| [`postfix-06-final.txt`](./postfix-06-final.txt) | entry/node lists, bootstrap-key sweep, host state, close-out |
| [`postfix-07-secret-scan.txt`](./postfix-07-secret-scan.txt) | five checks, full hex attribution, two live controls, finding S1 |


### Commands added by this re-verification

```sh
# redeploy
incus exec spike-broker -- systemctl stop incus-spiffe-broker.service
incus file push /tmp/incus-spiffe-broker-linux spike-broker/usr/local/bin/incus-spiffe-broker --mode 0755
incus exec spike-broker -- sha256sum /usr/local/bin/incus-spiffe-broker   # 4ed87f92…fa45
incus exec spike-broker -- systemctl restart incus-spiffe-broker.service

# prove the chain from nothing
spire-server agent evict -spiffeID .../spire/agent/x509pop/incus/a955ca30-...
incus exec spike-guest-a --project spike-spiffe -- env \
  SPIRE_SERVER_ADDRESS=10.55.156.67 SPIRE_SERVER_PORT=8081 \
  TRUST_DOMAIN=spike.incus.internal BROKER_CACERT=/root/p9/broker-ca.pem \
  /root/p9/guest-agent-bootstrap.sh          # no jq overrides

# non-root Workload API
useradd --system --no-create-home --shell /usr/sbin/nologin spike-workload   # uid 989
spire-server entry create -parentID <guest node> -spiffeID .../guest/demo-app \
  -selector unix:uid:989 -x509SVIDTTL 120
incus exec spike-guest-a --project spike-spiffe -- env NONROOT_USER=spike-workload \
  NONROOT_EXPECTED_SPIFFE_ID=.../guest/demo-app \
  /root/p9/guest-workload-check.sh .../guest/demo

# force the burn, then prove the nonce is spent
spire-server entry delete -entryID 70a95e01-...        # remove the exchange entry
#   redeem -> 503 {"error":"nonce_consumed_without_svid"}
spire-server entry create ...                          # restore it
#   replay the SAME nonce -> 409 {"error":"conflict"}

# retention, both ways
EXCHANGE_RETENTION=keep  /root/p9/guest-agent-bootstrap.sh
find /run/spike-exchange -type f -exec shred -u -z -n 1 {} + && umount /run/spike-exchange
```

### What this re-verification does NOT claim

- It does not close either **High** finding. `SEC-009 escalated` and `Broker blast radius`
  are architecture decisions, unchanged, and [`SECURITY_FINDINGS.md`](./SECURITY_FINDINGS.md)
  remains the authority on both.
- It does not re-run the deliberate stolen-nonce case (P8 **M1**, P10 case 5). The stakes
  recorded in [§ The case that is still open](#negative-checks) are unchanged.
- It does not claim cryptographic erasure anywhere. `shred(1)` on tmpfs is an overwrite plus
  an unlink; the observed end state is that the files were overwritten, the mount is gone and
  the path is empty. Nothing stronger.
- It does not re-test the guest **reboot** path or guest B; those transcripts above stand.

## Teardown inventory additions

Append to Appendix E. Ordered by the class each item belongs to.

**Class 1 (guests):**
- `spike-guest-a`: `/root/p9/` (harness + `broker-ca.pem`), `/var/lib/spire-agent/`
  (`agent-data.json`, `bundle.pem`), `/run/spike-p9/`, the empty `/run/spike-exchange/` directory,
  and a running `spire-agent` process. All are tmpfs or guest-disk only; no key material.
- `spike-guest-b`: `/root/p9/` (harness + `broker-ca.pem`). No agent was ever started there.

**Class 2 (broker/attestor, entries, nodes):**
- Registration entry `70a95e01-b401-4837-a963-c391aa61d8ff` — the exchange entry.
- Registration entry `718f0f2e-1430-4ea8-9179-ae7223724f6b` — the broker's own SVID entry.
- SPIRE node `spiffe://spike.incus.internal/spire/agent/x509pop/incus/a955ca30-a0dc-4087-a369-37d53d389c5a`
  — delete **before** the host node and before server removal.
- `spike-broker`: the `hostagent` disk device (`incus config device remove spike-broker hostagent`),
  the three `INCUS_SPIFFE_BROKER_{BROKER_SOCKET,WORKLOAD_API_SOCKET,AGENT_SPIFFE_ID}` lines in
  `/state/broker.env`, `/root/p8/operator-mint.sh`, and the `jq` package installed for the mint step.

**Post-fix re-verification additions and amendments:**
- The exchange registration entry ID is now `655e2c68-0a1f-423b-8cbd-bc6c7fc060c0`, NOT
  `70a95e01-…`: it was deleted and recreated for the burned-nonce proof. Same SPIFFE ID,
  parent, selector and TTL.
- `spike-guest-a` carries a system account `spike-workload` (uid 989, no home, no shell),
  created for the non-root Workload API proof. Its registration entry was deleted; the
  account remains and is harmless, but it is a spike artifact.
- `spike-guest-a`: `/tmp/spire-agent` and `/tmp/spire-agent/public` are mode `0701` rather
  than `0700`, so a non-root workload can traverse to the socket.
- The three harness files under `/root/p9/` on `spike-guest-a` were replaced with the
  commit `3f5b7f6` versions, and `spike-guest-b` was synced to the same three files (identical
  sha256) so P10 cannot hit the closed F2 trap on either guest. Harness sha256:
  `71f9ecb3…8589` bootstrap, `0194c9da…6b3a` workload-check, `35d94b32…2713` template.

**Class 3 (host agent volume) — new items on `spike-spire-agent-state`:**
- `/spike/bin/p9-wlapi-relay` (binary) and the running relay process inside the `spire-agent`
  container, plus the socket it created at `/spike/wlapi-relay.sock`. Killing the relay is enough to
  stop the identity fan-out; deleting the volume removes the rest.

## Handoff

**To P10, the adversarial and lifecycle matrix.** The chain is live and stable; start from it rather
than rebuilding it.

Standing state you inherit: broker **`4ed87f92…fa45`** (commit `3f5b7f6`) running with the three settings — `bd46b32d…` was replaced at 16:22 UTC; the exchange and
broker-SVID registration entries in place; `spike-guest-a` attested as
`…/spire/agent/x509pop/incus/a955ca30-…` with its agent running and its Workload API serving;
`spike-guest-b` staged with the same harness but never attested; the Workload API relay running
inside the `spire-agent` container.

Things P10 must know before writing its cases:

1. **Every guest bootstrap needs a fresh nonce.** There is no reusable credential on the guest.
   Mint with `operator-mint.sh` from inside `spike-broker`.
2. **CORRECTED — do NOT pass `CHAIN_JQ`/`KEY_JQ`/`BUNDLE_JQ`.** As originally written this
   item said the harness would not find the exchange material without them. That was true
   of the harness as it stood (finding F2) and is now **wrong and actively misleading**:
   at commit `3f5b7f6` the harness reads the broker's canonical field names
   `exchange_cert_chain_pem` / `exchange_key_pem` / `exchange_bundle_pem` first, and the
   overrides exist only for a broker that is not `cmd/incus-spiffe-broker`. Passing them is
   unnecessary. Proven live with none of them in
   [`postfix-02b-clean-run.txt`](./postfix-02b-clean-run.txt).
3. **The relay is load-bearing.** If the `spire-agent` container restarts, the relay dies and the
   broker loses its SVID; restart it with the command in
   [`deploy-05-workload-api-relay.txt`](./deploy-05-workload-api-relay.txt). This directly affects
   P10 case 2 (host agent container restart), which should assert on exactly this.
4. **Case 3 (guest reboot / agent restart) is already characterised here** —
   fresh-credential-per-boot, agent crashes with `unable to load keypair` if restarted without one.
   P10 should confirm it inside the full matrix rather than rediscover it.
5. **Case 4 (nonce replay) is already exercised** end to end within the full chain: HTTP `409`,
   exit `11`.
6. **Case 5 (wrong instance):** the two non-leak halves are done (N2, N3). The half that remains is
   the deliberate leak of an **unused** A nonce to B, and P9 raises its stakes — the prize is now a
   two-minute `x509pop` credential for A's node identity, not metadata.
7. **Case 7 (snapshot → restore)** should note that a plain `incus restart` does **not** move
   `volatile.uuid.generation`; the invalidation it tests must come from the restore, not the boot.
8. **A worthwhile case P9 could not reach:** force a node-SVID re-attestation while the exchange
   material is already destroyed, and record what the agent does. Source says it will reload the
   `x509pop` credential paths and find nothing (finding 5); nobody has watched it happen.
9. **Registration entries survive re-bootstrap.** Parent on the node SPIFFE ID, never on the
   `x509pop:serialnumber:` selector, which changes with every exchange certificate.

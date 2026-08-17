## Case 10 — Stale credentials

Live run on `ovh-incusos` (`ns1001912.ip-147-135-105.us`), project `spike-spiffe`, trust domain
`spike.incus.internal`, 2026-08-17 17:45–17:56 UTC. Direct observations below include HTTP
statuses and bodies, logs, bootstrap-key state, the repeated expired response, and reaper
withdrawal. Causal conclusions are labeled as inference. Per Appendix D no nonce value and no
private key appears in this directory: only nonce IDs, payload digests, certificate serials,
validity windows, SPIFFE IDs, selectors, HTTP statuses, and verbatim error strings.

**Verdict:** **PASS.** The plan expectation — *"Expired nonce, expired exchange SVID, and
revoked/deleted registration entry each fail cleanly with recorded errors."* — held for all three
stale states. Each refusal was explicit, carried a machine-readable code, produced no partial
identity, and left the system in a state a fresh bootstrap recovers from. The one lifecycle rough
edge is not new: deleting the registration entry burns the nonce that was in flight, which is the
documented P9 `F3` contract, now reached deliberately rather than incidentally.

| Stale state | Transport result | Code / reason | Identity produced |
|---|---|---|---|
| 1. Expired nonce | HTTP `409` | `{"error":"conflict"}`; broker reason `nonce: nonce expired` | none; nonce **not** consumed |
| 2. Expired exchange SVID | gRPC `PermissionDenied` | `nodeattestor(x509pop): certificate verification failed: x509: certificate has expired` | none; agent exited 1, node `NotFound` |
| 3. Deleted registration entry | HTTP `503` | `{"error":"nonce_consumed_without_svid"}`, `outcome=burned`, `failure_class=broker_no_svid` | none; nonce **burned** |

**Setup:**

- Starting point, verified at 17:44:10Z: two registration entries — broker `718f0f2e-1430-4ea8-9179-ae7223724f6b`
  (TTL 3600) and exchange `655e2c68-0a1f-423b-8cbd-bc6c7fc060c0` (selector
  `incus:uuid:a955ca30-a0dc-4087-a369-37d53d389c5a`, TTL 120), both parented to the `tpm_devid`
  host node; two attested nodes (host `tpm_devid/fee6de97…`, guest A `x509pop/incus/a955ca30-…`);
  guests A and B `RUNNING` with `user.spiffe-bootstrap` clear on both; broker
  `4ed87f92ca113334c2e2e60127ae00131a47273ac476dd1d2f05b8f2e463fa45` active.
- Tooling: the canonical P9 harness `spike/p9/guest-agent-bootstrap.sh` inside guest A and
  `spike/p8/operator-mint.sh` inside the broker container. No `CHAIN_JQ`, `KEY_JQ` or `BUNDLE_JQ`
  override was used anywhere in this unit. Only two harness knobs were set, and only for state 2:
  `AGENT_START_MODE=none` (stage the credential, start nothing) and `EXCHANGE_RETENTION=keep`
  (do not shred it, because the case must hold it until it expires).
- Not done by this unit, by contract: no host reboot, no `spire-server` / `spire-agent` container
  restart, no TPM command, no IncusOS security mutation, no deletion of guest A or B, no repository
  gate, formatter, code edit or Git command.

**Action:**

1. **Expired nonce** — mint for guest A with `MINT_TTL_SECONDS=15`, wait past `expires_at` but stay
   inside the broker's 2-minute reap grace so the record still exists, then redeem from inside
   guest A through its own `/dev/incus/sock`. Then redeem a second time, to test whether the first
   refusal mutated the record.
2. **Expired exchange SVID** — stop guest A's agent, evict its `x509pop` node and discard its agent
   data so that nothing but the exchange certificate could produce a node identity; mint a fresh
   nonce; stage the exchange credential into the guest tmpfs at mode 0600 with no agent started;
   wait past the leaf's `not_after` (entry TTL 120s); then run `spire-agent` and let `x509pop`
   present the expired certificate.
3. **Deleted registration entry** — record entry `655e2c68-0a1f-423b-8cbd-bc6c7fc060c0` in full,
   delete it, wait for the host agent to resync, mint a fresh nonce for guest A and redeem it.


**Expected:** (`SPIKE_PLAN.md`, P10 case matrix, row 10 — quoted verbatim)

> Expired nonce, expired exchange SVID, and revoked/deleted registration entry each fail cleanly with recorded errors.

**Observed:**

*1 — expired nonce* ([`case-10-01-expired-nonce.txt`](./case-10-01-expired-nonce.txt)). Minted
`nonce_id=8638a73759d2cd30f42bf26a032b6ae5`, `expires_at=2026-08-17T17:45:39.556449042Z`. Redeemed
at `17:46:19Z`, 40 seconds after expiry: **HTTP 409**, body `{"error":"conflict"}`, harness exit
`11`. Broker journal, verbatim:

```
{"level":"WARN","msg":"bootstrap request denied","operation":"redeem","outcome":"denied",
 "nonce_id":"8638a73759d2cd30f42bf26a032b6ae5","http_status":409,"code":"conflict",
 "reason":"nonce: consume nonce 8638a73759d2cd30f42bf26a032b6ae5: nonce: nonce expired: id 8638a73759d2cd30f42bf26a032b6ae5"}
```

**Observed:** The broker did not clear `user.spiffe-bootstrap`: the key remained present at 268
bytes with the same `nonce_id`. A second redemption at `17:46:50Z` was refused with the same
`nonce expired` reason, not `nonce already used`. No exchange SVID was observed and no node
appeared. At `17:47:46.537Z`, the ordinary reaper logged `"msg":"expired nonce withdrawn"` and
cleared the instance key.

**Causal inference:** The unchanged key and repeatable `nonce expired` response support the
conclusion that the refusal occurred before nonce consumption. They do not directly trace internal
ordering relative to the used-flag write or a Broker API call.

*2 — expired exchange SVID* ([`case-10-02-expired-exchange.txt`](./case-10-02-expired-exchange.txt)).
The staged credential, recorded by property only:

| Property | Value |
|---|---|
| exchange SPIFFE ID | `spiffe://spike.incus.internal/spire-exchange/incus/a955ca30-a0dc-4087-a369-37d53d389c5a` |
| serial | `70BD76E2A4C2E6743FAA1E891001A5DC` |
| `not_before` / `not_after` | `Aug 17 17:48:56 2026 GMT` / `Aug 17 17:51:06 2026 GMT` (130 s, entry TTL 120) |
| `exchange_expires_at` (broker field) | `2026-08-17T17:51:06Z` — matches the leaf |
| held as | `/run/spike-exchange/{svid.pem,svid.key}`, tmpfs, mode 0600, `nosuid,nodev,noexec` |
| current time at the attempt | `2026-08-17T17:52:00Z`, i.e. 54 s after `not_after` |

Agent, verbatim:

```
level=error msg="Agent crashed" error="failed to receive attestation response: rpc error:
  code = PermissionDenied desc = nodeattestor(x509pop): certificate verification failed:
  x509: certificate has expired or is not yet valid: current time 2026-08-17T17:52:00Z is
  after 2026-08-17T17:51:06Z"
```

Server, verbatim, for the same `request_id`:

```
ERRO Nodeattestor(x509pop): certificate verification failed: x509: certificate has expired or is
  not yet valid: current time 2026-08-17T17:52:00Z is after 2026-08-17T17:51:06Z
  authorized_as=nobody authorized_via= method=AttestAgent node_attestor_type=x509pop
  service=agent.v1.Agent
```

`authorized_as=nobody` is the whole point: the caller never became an identity. The agent exited
`1`, `spire-server agent list` reported **one** agent (the `tpm_devid` host node), and
`agent show -spiffeID …/x509pop/incus/a955ca30-…` returned `NotFound`. **No node identity was
issued from the expired material.** The certificate and key were then shredded and the tmpfs
unmounted; a filesystem sweep found zero `svid.pem`/`svid.key` on the guest, and the three residual
`PRIVATE KEY` string hits are attributed in the transcript (the Incus guest-agent binary, the Incus
guest-agent's own TLS key, and an apt package-description index) — none is exchange material.

*3 — deleted registration entry* ([`case-10-03-deleted-entry.txt`](./case-10-03-deleted-entry.txt)).
Entry `655e2c68-0a1f-423b-8cbd-bc6c7fc060c0` deleted at `17:53:04Z`. A fresh nonce
(`44004597b5e330ca9b790301ce0ae02c`) minted at `17:53:38Z` and redeemed at `17:53:40Z`:
**HTTP 503**, body `{"error":"nonce_consumed_without_svid"}`, harness exit `13`. Broker journal,
verbatim:

```
{"level":"INFO","msg":"bootstrap key cleared","operation":"redeem","nonce_id":"44004597b5e330ca9b790301ce0ae02c",…}
{"level":"ERROR","msg":"nonce consumed but no exchange SVID was issued","operation":"redeem",
 "outcome":"burned","nonce_id":"44004597b5e330ca9b790301ce0ae02c","failure_class":"broker_no_svid",
 "http_status":503,"code":"nonce_consumed_without_svid",
 "reason":"broker delivered no X.509-SVID: response carried an empty SVID list"}
```

That is exactly the expected `nonce_consumed_without_svid` / 503 / `outcome=burned` shape. The
authoritative datastore confirms the cause: `entry show -entryID 655e2c68-…` returns
`NotFound` and `entry show -spiffeID …/spire-exchange/incus/a955ca30-…` returns `Found 0 entries`,
so the host agent had nothing to have signed and answered the broker with an empty SVID list. No
node was created. **Disclosure:** two server-log capture blocks in that transcript came back empty
because the `spire-server` console ring buffer drained between reads; this is stated in the
transcript rather than quietly deleted, the affected counts are marked non-load-bearing, and the
server-side fact is taken from the datastore instead. The earlier server lines quoted for state 2
were read while the buffer still held them.

**Cleanup:**

- State 1 needed none: the broker's own reaper withdrew the expired nonce and cleared
  `user.spiffe-bootstrap`.
- State 2: the retained expired credential was shredded and its tmpfs unmounted, both verified —
  overwrite plus unlink on tmpfs, which is **not** cryptographic erasure and is not claimed to be.
- State 3: the exchange registration entry was recreated with the **same** SPIFFE ID, parent ID,
  selector `incus:uuid:a955ca30-a0dc-4087-a369-37d53d389c5a` and X509-SVID TTL `120`. SPIRE v1.15.2
  generates entry IDs server-side and the CLI cannot pin one, so the ID could not be preserved.
  **Replacement entry ID: `6261b897-9852-4740-a80f-2dbd05979597`** (original was
  `655e2c68-0a1f-423b-8cbd-bc6c7fc060c0`). The broker entry `718f0f2e-1430-4ea8-9179-ae7223724f6b`
  was never touched and keeps its original ID.
- Guest A was restored to a healthy attested state with a fresh nonce
  (`b4d8b11746c32018890c3a69f4eb7e9a`) and the canonical P9 harness at its defaults — no jq
  override, no `AGENT_START_MODE`, `EXCHANGE_RETENTION=shred`: `redeem: HTTP 200`, node
  `spiffe://spike.incus.internal/spire/agent/x509pop/incus/a955ca30-a0dc-4087-a369-37d53d389c5a`,
  Workload API healthy on `/tmp/spire-agent/public/api.sock`, exchange material shredded and
  unmounted, harness exit `0`.
- Final state at `17:55:45Z`: **two entries** (`718f0f2e-…` original, `6261b897-…` replacement with
  the original shape), **two attested nodes** (`tpm_devid/fee6de97…`, `x509pop/incus/a955ca30-…`),
  both guests `RUNNING`, both `user.spiffe-bootstrap` values clear, `/run/spike-exchange` empty and
  not a mount point, broker `active` at the unchanged digest
  `4ed87f92ca113334c2e2e60127ae00131a47273ac476dd1d2f05b8f2e463fa45`, host
  `tpm_status: ok`, `system_state_is_trusted: true`, `secure_boot_enabled: true`,
  root and swap `unlocked (TPM)`.

### Secret scan

Executed at 2026-08-17T17:57:52Z over exactly the four files this unit wrote. Every check runs with `-c`
(counts only), so the scan itself can never print a secret.

**The positive control is live, not synthetic.** A real nonce was minted for guest A with a
15-second TTL, its bootstrap payload was piped — never printed, never through argv — into a
mode-0600 file in a mode-0700 temporary directory, and the nonce value alone was written to a
pattern file used with `grep -F -f`. A throwaway 2048-bit RSA key supplies a real
`PRIVATE KEY` control. Control nonce_id `00e0882ad2a037d7f70ea21d217e84dc`. Observed shape of a
real nonce secret: **64 characters, all within `[A-Za-z0-9_-]`** — i.e. base64url, which is why
a hex-only pattern would be the wrong detector, and is not what is used here.

```
--- 1. does the detector actually fire? (positive controls, must be non-zero)
grep -F -f <nonce> control-payload.json      -> 1
grep -c "PRIVATE KEY" control-key.pem        -> 2
grep -cE "^[A-Za-z0-9+/=]{40,}$" control-key.pem -> 25

--- 2. the same detectors over the four evidence files (must all be 0)
live-nonce literal      case-10-stale-credentials.md       -> 0
live-nonce literal      case-10-01-expired-nonce.txt       -> 0
live-nonce literal      case-10-02-expired-exchange.txt    -> 0
live-nonce literal      case-10-03-deleted-entry.txt       -> 0
PRIVATE KEY / BEGIN RSA case-10-stale-credentials.md       -> 1
PRIVATE KEY / BEGIN RSA case-10-01-expired-nonce.txt       -> 0
PRIVATE KEY / BEGIN RSA case-10-02-expired-exchange.txt    -> 4
PRIVATE KEY / BEGIN RSA case-10-03-deleted-entry.txt       -> 0
BEGIN CERTIFICATE       case-10-stale-credentials.md       -> 0
BEGIN CERTIFICATE       case-10-01-expired-nonce.txt       -> 0
BEGIN CERTIFICATE       case-10-02-expired-exchange.txt    -> 0
BEGIN CERTIFICATE       case-10-03-deleted-entry.txt       -> 0
base64 blob line >=40   case-10-stale-credentials.md       -> 0
base64 blob line >=40   case-10-01-expired-nonce.txt       -> 0
base64 blob line >=40   case-10-02-expired-exchange.txt    -> 0
base64 blob line >=40   case-10-03-deleted-entry.txt       -> 0
base64url token len 64  case-10-stale-credentials.md       -> 2
base64url token len 64  case-10-01-expired-nonce.txt       -> 4
base64url token len 64  case-10-02-expired-exchange.txt    -> 4
base64url token len 64  case-10-03-deleted-entry.txt       -> 7

--- 3. attribution of every 64-character token found (the nonce shape)
  4ed87f92ca113334c2e2e60127ae00131a47273ac476dd1d2f05b8f2e463fa45  64-hex -> a SHA-256 digest (payload/binary/fingerprint), permitted by Appendix D rule 3
  5fe7bc58c92f1dff2d5ef89f359f83c7c44035fc15d76900a9d55e517a4567f1  64-hex -> a SHA-256 digest (payload/binary/fingerprint), permitted by Appendix D rule 3
  6382c8a2912fcdb7730a25d4d9a2b753644a4a89380edfaf6c3b157203ea9cf5  64-hex -> a SHA-256 digest (payload/binary/fingerprint), permitted by Appendix D rule 3
  7cedc92f3e349063cfd060bbe8be4da00dcab4b12b164d765ca926b05147ab93  64-hex -> a SHA-256 digest (payload/binary/fingerprint), permitted by Appendix D rule 3
  905fef8427e1e1eb63fd0402816e051c989c8a2024dda8dcd7b157b2f125527b  64-hex -> a SHA-256 digest (payload/binary/fingerprint), permitted by Appendix D rule 3
  9eb18b1a93682960e9e190cd818284ad4bcaf1740be9a435630a3b1dc60acee7  64-hex -> a SHA-256 digest (payload/binary/fingerprint), permitted by Appendix D rule 3
  a81803ca5a6670820853098dc76f69224df199dd7d50da1199a62bc941186380  64-hex -> a SHA-256 digest (payload/binary/fingerprint), permitted by Appendix D rule 3

--- 4. bearer-token and key-field names must not appear with a value
"nonce":"<value>" pattern case-10-stale-credentials.md     -> 0
"nonce":"<value>" pattern case-10-01-expired-nonce.txt     -> 0
"nonce":"<value>" pattern case-10-02-expired-exchange.txt  -> 0
"nonce":"<value>" pattern case-10-03-deleted-entry.txt     -> 0
exchange_key_pem w/ value case-10-stale-credentials.md     -> 0
exchange_key_pem w/ value case-10-01-expired-nonce.txt     -> 0
exchange_key_pem w/ value case-10-02-expired-exchange.txt  -> 0
exchange_key_pem w/ value case-10-03-deleted-entry.txt     -> 0
```

**Reading the counts.** Every secret-bearing detector is zero on every one of the four files:
the live nonce literal, `BEGIN CERTIFICATE`, any base64 blob line of 40+ characters, a `nonce`
JSON field carrying a value, and an `exchange_key_pem` field carrying a value. The same
detectors fire on the controls (1, 2 and 25 hits), so the scan is not vacuous.

Two counts are non-zero and both are prose, verified line by line:

- `PRIVATE KEY` matches the ENGLISH PHRASE only — the harness warning "the exchange PRIVATE KEY
  is LIVE in /run/spike-exchange", the sweep command `grep -rl "PRIVATE KEY" /run /var/lib`, and
  its attribution heading. There is no PEM block anywhere: `BEGIN CERTIFICATE` and the base64
  blob detector are both 0 on all four files. The count for the fragment itself rose from 1 to 4
  the moment this section was appended, because this section discusses the phrase; the scan is
  self-referential and that is stated rather than hidden.
- 64-character tokens are all 64-HEX, and hex is not the nonce alphabet. Each one is attributed
  above: the broker binary digest, the broker TLS fingerprint, the guest base image digest, and
  four bootstrap-payload SHA-256 digests. A real nonce is 64 characters of base64url and would
  fail the `^[a-f0-9]{64}$` test, which is exactly what the attribution loop checks for.

**Scan verdict: CLEAN.** No nonce value, no private key, no certificate and no credential
response body is present in any of the four files.

Control teardown, executed at 2026-08-17T18:01:39Z:

```
control files shredded; control dir exists? no
control nonce 00e0882ad2a037d7f70ea21d217e84dc, broker journal:
{"time":"2026-08-17T17:57:29.051303896Z","level":"INFO","msg":"bootstrap nonce minted","operation":"mint","nonce_id":"00e0882ad2a037d7f70ea21d217e84dc","instance_uuid":"a955ca30-a0dc-4087-a369-37d53d389c5a","instance_name":"spike-guest-a","generation":"c32efc7b-f3d8-4637-9818-f8906c35543a","project":"spike-spiffe","expires_at":"2026-08-17T17:57:44.036328599Z"}
{"time":"2026-08-17T17:59:46.595632595Z","level":"INFO","msg":"expired nonce withdrawn","operation":"reap","nonce_id":"00e0882ad2a037d7f70ea21d217e84dc","instance_uuid":"a955ca30-a0dc-4087-a369-37d53d389c5a","project":"spike-spiffe","expires_at":"2026-08-17T17:57:44.036328599Z","instance_name":"spike-guest-a"}
user.spiffe-bootstrap on guest A -> []
user.spiffe-bootstrap on guest B -> []
```

### Closing verification, after the scan and its control teardown

```
now=2026-08-17T18:01:55Z
Found 2 entries
Entry ID                : 718f0f2e-1430-4ea8-9179-ae7223724f6b
SPIFFE ID               : spiffe://spike.incus.internal/incus-broker
Parent ID               : spiffe://spike.incus.internal/spire/agent/tpm_devid/fee6de975fb82fdbd3c7b7ea7e0b752412469fd0
X509-SVID TTL           : 3600
Selector                : unix:uid:0
Entry ID                : 6261b897-9852-4740-a80f-2dbd05979597
SPIFFE ID               : spiffe://spike.incus.internal/spire-exchange/incus/a955ca30-a0dc-4087-a369-37d53d389c5a
Parent ID               : spiffe://spike.incus.internal/spire/agent/tpm_devid/fee6de975fb82fdbd3c7b7ea7e0b752412469fd0
X509-SVID TTL           : 120
Selector                : incus:uuid:a955ca30-a0dc-4087-a369-37d53d389c5a
Found 2 attested agents:
SPIFFE ID         : spiffe://spike.incus.internal/spire/agent/tpm_devid/fee6de975fb82fdbd3c7b7ea7e0b752412469fd0
Attestation type  : tpm_devid
SPIFFE ID         : spiffe://spike.incus.internal/spire/agent/x509pop/incus/a955ca30-a0dc-4087-a369-37d53d389c5a
Attestation type  : x509pop
3525 spire-agent run -config /run/spike-p9/agent.conf
Agent is healthy.
spike-authz-probe,RUNNING,CONTAINER (APP)
spike-guest-a,RUNNING,VIRTUAL-MACHINE
spike-guest-b,RUNNING,VIRTUAL-MACHINE
{"tpm_status":"ok","system_state_is_trusted":true}
active
4ed87f92ca113334c2e2e60127ae00131a47273ac476dd1d2f05b8f2e463fa45  /usr/local/bin/incus-spiffe-broker
```

Not done by this unit, by contract: no host reboot, no `spire-server`/`spire-agent` container
restart, no snapshot, clone or instance deletion, no `tpm2_*` command, no `/dev/tpmrm0` access,
no IncusOS security mutation, no change to `/state/broker.env` or any broker flag, no repository
gate, formatter, code edit or Git command. The only durable changes are this evidence and the
replacement exchange entry ID `6261b897-9852-4740-a80f-2dbd05979597`.

### Post-edit re-verification of the scan

The fragment was edited after the scan ran, to put the plan quotation on a single verbatim line.
The live-nonce control had already been destroyed by then, so instead of pretending to re-run it,
the structural detectors were re-run over the final bytes of all four files, and every
64-character token was re-attributed. The edit added prose only.

```
now=2026-08-17T18:02:47Z
BEGIN CERTIFICATE / base64 blob>=40  case-10-stale-credentials.md       -> 6 / 0
BEGIN CERTIFICATE / base64 blob>=40  case-10-01-expired-nonce.txt       -> 0 / 0
BEGIN CERTIFICATE / base64 blob>=40  case-10-02-expired-exchange.txt    -> 0 / 0
BEGIN CERTIFICATE / base64 blob>=40  case-10-03-deleted-entry.txt       -> 0 / 0
"nonce" field with a value          case-10-stale-credentials.md       -> 0
"nonce" field with a value          case-10-01-expired-nonce.txt       -> 0
"nonce" field with a value          case-10-02-expired-exchange.txt    -> 0
"nonce" field with a value          case-10-03-deleted-entry.txt       -> 0
every 64-char token, non-hex count (must be 0): 0
distinct 64-char tokens: 7 (all 64-hex SHA-256 digests, attributed above)
```

Scan verdict after the edit: **still CLEAN**.

**The `6` needs saying plainly.** It is the same self-reference as the `PRIVATE KEY` count: the
string `BEGIN CERTIFICATE` now occurs six times in THIS fragment because the scan section names
the detector. The detector that cannot be self-referenced is the PEM delimiter itself, and it is
zero everywhere:

```
literal PEM delimiter -----BEGIN  case-10-stale-credentials.md       -> 0
literal PEM delimiter -----BEGIN  case-10-01-expired-nonce.txt       -> 0
literal PEM delimiter -----BEGIN  case-10-02-expired-exchange.txt    -> 0
literal PEM delimiter -----BEGIN  case-10-03-deleted-entry.txt       -> 0
```

No PEM object of any kind exists in the four files.

## Case 4 — Nonce replay (reuse after redemption)

**Verdict:** PASS

**Setup:** Live chain on `ovh-incusos` (IncusOS `202608102114`, Incus 7.3, SPIRE 1.15.2, trust
domain `spike.incus.internal`), 2026-08-17 17:02–17:05 UTC. The whole chain is in place: the
physically attested host node `…/spire/agent/tpm_devid/fee6de975fb82fdbd3c7b7ea7e0b752412469fd0`,
the broker `spiffe://spike.incus.internal/incus-broker` (binary
`4ed87f92ca113334c2e2e60127ae00131a47273ac476dd1d2f05b8f2e463fa45`), and the two registration
entries `718f0f2e-1430-4ea8-9179-ae7223724f6b` and `655e2c68-0a1f-423b-8cbd-bc6c7fc060c0`
(X509-SVID TTL 120), both parented to the `tpm_devid` node.

To prove the chain **from nothing** rather than from P9's residue, guest A was reset first
([`case-04-01-reset.txt`](./case-04-01-reset.txt)): the P9 agent process (`pid 2650`) was killed,
`/var/lib/spire-agent`, `/run/spike-p9` and `/tmp/spire-agent` were removed, and the guest node was
**evicted** (not banned) so the next attestation is a first attestation. The server then listed
`Found 1 attested agent` — the host only — and `user.spiffe-bootstrap` on A was `<unset>`.

P8 proved replay rejection against the broker in isolation. This case re-runs it inside the
complete chain: host agent → broker → Broker API → SPIRE server → guest `x509pop` node → guest
Workload API.

**Action:**
1. Minted exactly one nonce for `spike-guest-a` through the authenticated operator endpoint
   (`MINT_AUTH_TOKEN_FILE=/state/auth/mint-token`), then copied the resulting
   `user.spiffe-bootstrap` value out of Incus **before** redemption so the identical nonce value
   would still exist for step 3. The copy was made by piping `incus config get` stdout straight
   into the guest's stdin (`sh -c 'umask 077; cat > /run/replay-payload.json'`) — the value never
   entered argv, a shell variable, or this transcript.
2. Ran `spike/p9/guest-agent-bootstrap.sh` inside guest A with **no** `CHAIN_JQ`, `KEY_JQ`,
   `BUNDLE_JQ`, no `PAYLOAD_FILE`, and no hand-editing, reading the nonce from its own
   `/dev/incus/sock`.
3. Replayed the **same** nonce value twice: once through the harness with
   `PAYLOAD_FILE=/run/replay-payload.json`, and once as a raw `curl` `POST /v1alpha1/redeem` whose
   `{nonce_id, nonce}` body was built by `jq` from that file and piped in on stdin, so the verbatim
   HTTP status and response body could be recorded.

**Expected:** The plan's expected outcome for case 4 is, verbatim: "Rejected (P8 re-run within full
chain)". Concretely, per the P9 contract: the first redemption succeeds end to end and consumes
the nonce. Replaying that already-used nonce returns HTTP `409` with body exactly
`{"error":"conflict"}`: replay rejected before any new consume/Broker call, not consumed by this
request and then failed during issuance with `{"error":"nonce_consumed_without_svid"}`.

**Observed:**

*Step 2, the full chain, completed on the first attempt* — [`case-04-02-chain.txt`](./case-04-02-chain.txt):

- mint: `HTTP 201`, `nonce_id=6f6a834cc2d0fc807fd9bf14f91a24ad`,
  `expires_at=2026-08-17T17:13:21.269029225Z`; the mint response carried no nonce, secret or token
  field.
- guest socket read: `socket_read: GET /1.0/config/user.spiffe-bootstrap -> HTTP 200`.
- broker leaf pinned before the nonce was transmitted: expected and observed fingerprint both
  `7cedc92f3e349063cfd060bbe8be4da00dcab4b12b164d765ca926b05147ab93`, SPKI pin
  `sha256//VgsjkxXQUOpcDDf3ME0k558xOPa4eQlShWxr+H0l/DA=`.
- `redeem: HTTP 200`, `verdict: GRANTED`, and six selectors derived host-side, the guest supplying
  none of them: `incus:uuid:a955ca30-a0dc-4087-a369-37d53d389c5a`,
  `incus:generation:c32efc7b-f3d8-4637-9818-f8906c35543a`, `incus:project:spike-spiffe`,
  `incus:type:virtual-machine`, `incus:name:spike-guest-a`,
  `incus:image:9eb18b1a9368…60acee7`.
- `exchange_spiffe_id` matched exactly as required:
  `spiffe://spike.incus.internal/spire-exchange/incus/a955ca30-a0dc-4087-a369-37d53d389c5a`,
  read from the certificate as well as the JSON field; serial `2D08426416B482C5FE72B49873491465`,
  `not_before=Aug 17 17:03:28 2026 GMT not_after=Aug 17 17:05:38 2026 GMT` (130 s).
- the guest agent attested:
  `agent: node attestation succeeded, node_spiffe_id=spiffe://spike.incus.internal/spire/agent/x509pop/incus/a955ca30-a0dc-4087-a369-37d53d389c5a`,
  healthcheck ready on the standard `/tmp/spire-agent/public/api.sock`.
- `RESULT phase=p9-bootstrap outcome=PASS … exchange_retention=shred exchange_material=shredded-and-unmounted`,
  `EXIT=0`.
- `spire-server agent list` → `Found 2 attested agents`: the `tpm_devid` host node and
  `…/spire/agent/x509pop/incus/a955ca30-a0dc-4087-a369-37d53d389c5a` (`x509pop`, serial
  `136539776118668358900007883244891863334`).
- `user.spiffe-bootstrap` on A after redemption: `<unset>` — cleared by the broker.

*Step 3, the replay, was refused* — [`case-04-03-replay.txt`](./case-04-03-replay.txt):

- The staged copy still named the consumed nonce: `nonce_id=6f6a834cc2d0fc807fd9bf14f91a24ad`,
  fields `broker_fingerprint,broker_url,nonce,nonce_id`. It is the same nonce value the broker had
  just granted.
- Harness replay: `redeem: HTTP 409`, then
  `RESULT phase=p9-bootstrap outcome=ERROR reason=redeem_rejected status=409 nonce_id=6f6a834cc2d0fc807fd9bf14f91a24ad broker_reason=conflict`,
  `EXIT=11`.
- Raw wire capture: `HTTP_STATUS=409`, `RESPONSE_BODY_BYTES=21`, body byte-for-byte:

  ```
  {"error":"conflict"}
  ```

  A `grep -c -E "exchange_|PRIVATE KEY|nonce\""` over the refusal body returned `0`: the refusal
  carries no credential material.
- Broker log, both refusals, verbatim:

  ```
  {"time":"2026-08-17T17:04:17.617743892Z","level":"WARN","msg":"bootstrap request denied","operation":"redeem","outcome":"denied","nonce_id":"6f6a834cc2d0fc807fd9bf14f91a24ad","instance_uuid":"a955ca30-a0dc-4087-a369-37d53d389c5a","peer_address":"10.55.156.150:42400","http_status":409,"code":"conflict","reason":"nonce: consume nonce 6f6a834cc2d0fc807fd9bf14f91a24ad: nonce: nonce already used: id 6f6a834cc2d0fc807fd9bf14f91a24ad"}
  {"time":"2026-08-17T17:04:47.405727818Z","level":"WARN","msg":"bootstrap request denied","operation":"redeem","outcome":"denied","nonce_id":"6f6a834cc2d0fc807fd9bf14f91a24ad","instance_uuid":"a955ca30-a0dc-4087-a369-37d53d389c5a","peer_address":"10.55.156.150:45266","http_status":409,"code":"conflict","reason":"nonce: consume nonce 6f6a834cc2d0fc807fd9bf14f91a24ad: nonce: nonce already used: id 6f6a834cc2d0fc807fd9bf14f91a24ad"}
  ```

- A `grep -c` for `outcome":"burned` and `nonce_consumed_without_svid` across the whole 15-minute
  window returned `0`. **No burn path was taken.**

**The replay denial is externally distinguishable from a burn.** P9's code fix (P9
`SECURITY_FINDINGS.md`, "Burned-nonce retry semantics", and P9 `EVIDENCE.md` A15) made the two
outcomes separate observable contracts:

| | Replay of an already-used nonce | Nonce consumed by this request, then issuance failed |
|---|---|---|
| HTTP status | `409` | `503` (or `500`) |
| Body | `{"error":"conflict"}` | `{"error":"nonce_consumed_without_svid"}` |
| Log level | `WARN` | `ERROR` |
| Log `outcome` | `denied` | `burned` |
| Extra log fields | `code`, `reason` | `failure_class`, `nonce_id`, `instance_uuid` |

Both replays produced the left column: `409`, `{"error":"conflict"}`, `WARN`, and
`outcome=denied`. The external `409`/`conflict` contract distinguishes this denial from the
`500`/`503` burn contract, while the sanitized internal `nonce already used` reason proves the
exact cause. The consume operation returned `already used`, so each replay was rejected before
any new consume/Broker call and no exchange SVID was requested. Neither replay spent anything
additional; the original successful request consumed the nonce. Guest A's working node identity
remained attested throughout.

Case 4 therefore proves replay rejection at the broker gate in a fully established chain. It does
not test replay of an exchange certificate.

**Cleanup:** The staged copy of the nonce was destroyed with `shred -zu /run/replay-payload.json`;
`ls -l /run/replay-payload.json` then returned
`ls: cannot access '/run/replay-payload.json': No such file or directory`
([`case-04-03-replay.txt`](./case-04-03-replay.txt) step 6). No registration entry was added,
removed or modified in this case. Guest A is left attested with a live node
`…/spire/agent/x509pop/incus/a955ca30-a0dc-4087-a369-37d53d389c5a` and a serving Workload API;
`user.spiffe-bootstrap` on A is `<unset>`. `/run/spike-exchange` was shredded and unmounted by the
harness in both runs.

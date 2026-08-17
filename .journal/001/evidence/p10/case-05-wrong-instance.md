## Case 5 — Wrong instance (credential-origin binding)

**Verdict:** FINDING

Q1 and Q2 pass their boundaries. Q3 reproduces, deliberately and inside the complete P9/P10
chain, the bearer-token result the plan told this case to measure rather than expect to fail.

**Setup:** Live chain on `ovh-incusos` (IncusOS `202608102114`, Incus 7.3, SPIRE 1.15.2, trust
domain `spike.incus.internal`), 2026-08-17 18:07–18:13 UTC. Nothing was created or destroyed for
this case beyond one mode-0700 tmpfs scratch directory inside guest B.

| | |
|---|---|
| Guest A | `spike-guest-a`, `volatile.uuid` `a955ca30-a0dc-4087-a369-37d53d389c5a`, generation `c32efc7b-f3d8-4637-9818-f8906c35543a`, RUNNING |
| Guest B | `spike-guest-b`, `volatile.uuid` `a4fec3ea-d4aa-4e6c-94c6-8295cee62338`, generation `a4fec3ea-d4aa-4e6c-94c6-8295cee62338`, RUNNING |
| Host node | `spiffe://spike.incus.internal/spire/agent/tpm_devid/fee6de975fb82fdbd3c7b7ea7e0b752412469fd0` |
| Broker | `https://10.55.156.44:8443`, binary `4ed87f92ca113334c2e2e60127ae00131a47273ac476dd1d2f05b8f2e463fa45` |
| Entries | `718f0f2e-1430-4ea8-9179-ae7223724f6b` (broker, TTL 3600) and `6261b897-9852-4740-a80f-2dbd05979597` (exchange, TTL 120, selector `incus:uuid:a955ca30-…`) |
| Bootstrap keys at start | A `<unset>`, B `<unset>` ([`case-05-01`](./case-05-01-guest-socket.txt) §1.3) |

Both entries are parented to the physically attested `tpm_devid` node. **The only exchange entry
in the server is scoped to A's UUID; there is no entry for B's UUID.** That asymmetry is what
makes Q2 legible: a correctly resolved B binding has nothing to issue against, so the broker's
own resolution — not a coincidental success — becomes the observable.

No second SPIRE agent was started at any point. This case does not re-prove P8's transferred-value
redemption or P9's `x509pop` completion; it establishes the credential-origin binding facts and
then composes the two already-observed contracts.

**Action:** Seven actions, no more. Scratch was a `tmpfs` mounted at `/run/p10c5` in guest B
(`size=1m,mode=0700,nosuid,nodev,noexec`), every file mode 0600. No `set -x`, no `curl -v`, no
`--trace`; response bodies reached `--output` files only, with `--write-out '%{http_code}'` the
sole thing on stdout.

1. Recorded A/B identity, host node, broker digest, entry IDs; confirmed both bootstrap keys
   clear; prepared the tmpfs.
2. Minted one bootstrap value for A (`nonce_id=d674d58ac0450aa9bbe3242daf9d3188`,
   `expires_at=2026-08-17T18:18:21.141752703Z`) and left it unredeemed. From B, queried
   `user.spiffe-bootstrap` through **B's own** `/dev/incus/sock`.
3. Minted B's own material (`nonce_id=e91f85e8af07a606a5a0952b62620fb9`), read it in B from B's
   own socket into 0600 scratch, and built a redeem body carrying A's UUID as an extra claimed
   field with `jq`, file-to-file — never argv, never a shell variable.
4. Submitted that body from B, then submitted the same nonce again in a clean body.
5. Transferred A's still-unused value directly into B's scratch by piping `incus config get`
   stdout into `incus exec … 'umask 077; cat > /run/p10c5/a-payload.json'`.
6. Redeemed it from B with raw `curl`, keeping the successful body in scratch only.
7. Shredded and unmounted everything, cleared both keys, and proved final state.

**Expected:** The plan's expected outcome for case 5 is, verbatim: "B cannot read A's nonce; B's
own nonce cannot request A's identity. Separately record that theft of an unused A bearer nonce
can impersonate A unless an additional caller-binding mechanism is proven".

**Observed:**

### Q1 — B's socket shows B, never A ([`case-05-01`](./case-05-01-guest-socket.txt))

While A carried an outstanding, unredeemed value, B's own guest socket answered:

- `socket_read(B, user.spiffe-bootstrap): HTTP 404`, 10 response bytes.
- `b_sees_A_outstanding_value=false` — a `grep -F` for A's `nonce_id` in B's socket response found
  nothing.
- `b_sees_any_bootstrap_payload=false`.
- `GET /1.0/config` → `HTTP 200`, `visible_key_count=0`: B's entire guest-visible config namespace
  is empty, so there is no other representation of A's value to reach either.
- `GET /1.0` → `{"api_version":"1.0","instance_type":"virtual-machine","state":"Started"}`: the
  endpoint B is talking to is B's own.

B saw its own clear key and never A's outstanding value. **Q1 passes.**

### Q2 — B's own material binds to B; the claim is refused outright ([`case-05-02`](./case-05-02-own-material.txt))

| | |
|---|---|
| Source UUID (where the request came from) | `a4fec3ea-d4aa-4e6c-94c6-8295cee62338` (B) |
| Claimed UUID (extra body field) | `a955ca30-a0dc-4087-a369-37d53d389c5a` (A) |
| Authoritative bound UUID | `a4fec3ea-d4aa-4e6c-94c6-8295cee62338` (B) |
| Claimed-UUID submission | HTTP `400`, `{"error":"invalid_request"}`, `outcome=denied`, reason `decode request body: json: unknown field "instance_uuid"` |
| Clean submission | HTTP `503`, `{"error":"nonce_consumed_without_svid"}`, `outcome=burned`, `failure_class=broker_no_svid`, reason `broker delivered no X.509-SVID: response carried an empty SVID list` |
| A exchange identity issued | **No** — 0 `exchange_spiffe_id` log lines in the window; both response bodies contained 0 credential-shaped fields |
| B exchange identity issued | **No** — no entry carries selector `incus:uuid:a4fec3ea-…` |

The claimed identity is **refused, not ignored**. The redeem decoder calls
`DisallowUnknownFields` (`cmd/incus-spiffe-broker/service.go:1233`) and `redeemRequest` has no
`instance_uuid` member at all (`service.go:335-351`), so the request died at decode, before any
nonce state was touched. That is stronger than P8's case (h), where a claimed UUID was accepted
into the body and then ignored during resolution.

**Status alone is not the proof, and the plan says so.** The `503` is the *post-consumption* burn,
which by construction happens only after the broker has already resolved the binding. Two log
fields carry that resolution: the burn line names `instance_uuid=a4fec3ea-…` — B — and the
preceding `bootstrap key cleared` line names `instance_name=spike-guest-b`, i.e. the broker went
back to **B's own** config key to clear it. The failure class is `broker_no_svid`: no registration
entry matched B's independently derived selectors. It is not "A's identity was refused at the last
moment"; A's UUID never entered the resolution at all. **Q2 passes.**

### Q3 — A's deliberately transferred unused value is fully portable ([`case-05-03`](./case-05-03-deliberate-transfer.txt))

A's value from action 2 was still unredeemed. It was moved into B on purpose, with no stdout,
argv, shell-variable or evidence exposure, landing as a 268-byte mode-0600 file on B's tmpfs.
Only `nonce_id=d674d58ac0450aa9bbe3242daf9d3188` and `transfer_was_deliberate=true` were recorded.

Redeemed from B by raw `curl`, with the successful body written straight to 0600 scratch and never
printed:

```text
HTTP_STATUS=200
authoritative_bound_instance_uuid=a955ca30-a0dc-4087-a369-37d53d389c5a
authoritative_bound_instance_name=spike-guest-a
exchange_spiffe_id=spiffe://spike.incus.internal/spire-exchange/incus/a955ca30-a0dc-4087-a369-37d53d389c5a
cert_uri_san=spiffe://spike.incus.internal/spire-exchange/incus/a955ca30-a0dc-4087-a369-37d53d389c5a
cert_serial=FDBE9594B7A37911FBF11A1990FDC3A5
cert_not_before=Aug 17 18:10:13 2026 GMT
cert_not_after=Aug 17 18:12:23 2026 GMT
key_matches_certificate=true
chain_verifies=true
```

HTTP 200, bound UUID A, URI SAN
`spiffe://spike.incus.internal/spire-exchange/incus/a955ca30-a0dc-4087-a369-37d53d389c5a`, and
both checks true — exactly the expectation. The leaf was valid for 130 seconds.
`spire_agent_processes_in_B=0` throughout; `/var/lib/spire-agent` and `/tmp/spire-agent` never
existed in B.

**[INFERENCE from observed P8 + P9 contracts]** No agent was started, so this case does not itself
observe B becoming A's node. The consequence composes two contracts already observed:

- **P8** observed that possession of an unused nonce, not caller location, controls redemption:
  a transferred A payload redeemed from B returned A's binding and all six selectors
  (p8 `matrix-run1-abdefghi.txt` case (i); p8 `SECURITY_FINDINGS.md`, "Bearer-token risk").
- **P9** observed that exactly this credential format — leaf with URI SAN
  `spiffe://<td>/spire-exchange/incus/<uuid>`, matching unencrypted PKCS#8 key, trust bundle —
  completes `x509pop` `mode="spiffe"` and yields the derived node
  `spiffe://<td>/spire/agent/x509pop/incus/<uuid>` (p9 `chain-03-guest-bootstrap.txt`,
  `chain-04-agent-list.txt`; p9 `SECURITY_FINDINGS.md`, "SEC-009 escalated").

The credential obtained inside B satisfies P9's input contract on every field checked:
correct URI SAN for A, `key_matches_certificate=true`, `chain_verifies=true` against the server's
own bundle. A holder in B could therefore complete `x509pop` as A's node. That is an inference
composed from prior live results, not a new live claim here.

### What separates Q1/Q2 from Q3

Q1 and Q2 are boundaries on **caller assertion and caller location**: B cannot see A's value
through the guest API, and B cannot name A in a request. Q3 is a boundary on **possession**, and
there is none. Every control the design does have — server-side UUID resolution, single use, a
600-second nonce TTL, a 130-second exchange TTL, per-instance guest-socket visibility, and the
reaper — constrains normal delivery and the exposure window. None of them distinguishes the
intended guest from another caller holding the same unused value, because nothing in the
redemption is bound to anything only A can produce. Closing Q3 requires an additional
caller-binding mechanism, which remains unbuilt: SEC-009's disposition and the P9 escalation are
unchanged by this case, and this case is the third independent live confirmation of them.

**Cleanup** ([`case-05-04`](./case-05-04-cleanup.txt)): all 17 scratch files, including A's
payload, request body, response, chain, key and bundle, were `shred -zu`-ed; the tmpfs was
unmounted and the directory removed (`findmnt` → no such mount, path absent). Stated no more
strongly than P9 allows: this proves namespace removal, not cryptographic erasure, and tmpfs pages
can swap. Both bootstrap keys were verified `<unset>` (the broker had cleared each on redemption).
Both registration entries are unchanged in ID, SPIFFE ID, parent, TTL and selector. `agent list`
still shows exactly two nodes: the `tpm_devid` host and A's
`…/spire/agent/x509pop/incus/a955ca30-…` at unchanged serial
`142664646892380702363741184904059716611`; guest A still runs one `spire-agent` with a live
Workload API socket. B has 0 `spire-agent` processes, no agent state directory, and no `api.sock`.
The host reports `tpm_status: ok`, `system_state_is_trusted: true`, root and swap
`unlocked (TPM)`, Secure Boot enabled. The host `tpm_devid` node SVID rotated on its own schedule
during the case (serial and expiry moved, SPIFFE ID byte-identical); that is routine rotation, not
an effect of this case.

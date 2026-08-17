# P8 — Guest VM binding and one-time nonce lifecycle, live run — 2026-08-17 03:50–04:04 UTC on `ovh-incusos` (`ns1001912.ip-147-135-105.us`, Incus server 7.3, x86_64)

**Re-verified 2026-08-17 04:45–05:04 UTC** against a hardened binary, after an independent security
review found nine defects in the code this run exercised. The original run is preserved as written;
the claims it made that are no longer true are annotated **Superseded** where they appear, and the
second run is recorded in [§ Post-hardening
re-verification](#post-hardening-re-verification-2026-08-17).

Companion documents, neither rewritten here:
[`GUEST_SOCK_BRIEF.md`](./GUEST_SOCK_BRIEF.md) (source-cited Incus 7.3 guest-socket contract) and
[`SECURITY_FINDINGS.md`](./SECURITY_FINDINGS.md) (the independent review, including the two High
findings — SEC-009 and SEC-001 — that were deliberately **not** fixed in code).

## Scope

Deploy `cmd/incus-spiffe-broker` onto the live host, prove that a guest can be bound to its Incus
instance through `/dev/incus/sock` plus a `user.spiffe-bootstrap` nonce, and exercise every
lifecycle case named in `SPIKE_PLAN.md` lines 216–231 (P8 steps 1–5): positive redemption,
sequential reuse, expiry, genuinely concurrent redemption, deleted instance, generation change,
per-instance delivery, an untrusted UUID claim, and the deliberate bearer-token leak.

In scope: broker deployment and configuration, TLS and credential split, mint/redeem transcripts,
the nonce lifecycle matrix, the bearer-token measurement, cleanup, and an executed secret scan.

Out of scope: guest-local SPIRE agent and `x509pop` bootstrap (P9), any TPM operation, any host
mutation, any change to the code worktree, any repository gate, any Git command.

Everything below was observed on the live host. Anything not directly observed is marked
`[INFERENCE]`. Per Appendix D no nonce value appears anywhere in this directory; nonce **IDs** and
payload **SHA-256 digests** are recorded instead, and [§ Secret handling](#secret-handling) shows
the scan that was run to confirm it.

## Acceptance result

| # | Criterion (`SPIKE_PLAN.md` P8) | Verdict | Evidence |
|---|---|---|---|
| A1 | **Positive redemption** — broker writes the key, the guest reads it through its own `/dev/incus/sock`, the broker resolves A and grants an identity | **PASS** | [`positive-01-mint.txt`](./positive-01-mint.txt), [`positive-02-host-key-set.txt`](./positive-02-host-key-set.txt), [`positive-03-guest-redeem.txt`](./positive-03-guest-redeem.txt), [`positive-04-key-cleared.txt`](./positive-04-key-cleared.txt) — HTTP 201 then HTTP 200 with six `incus:` selectors |
| A2 | **Atomic single use** — concurrent redemption yields exactly one success | **PASS** | [`case-d-strict-concurrency.txt`](./case-d-strict-concurrency.txt) — three rounds, POSTs ≤ 0.7 ms apart, `200/409` every time; also [`matrix-run1-abdefghi.txt`](./matrix-run1-abdefghi.txt) case d |
| A3 | **Expiry honoured** | **PASS** | [`case-c-expiry.txt`](./case-c-expiry.txt) — HTTP 409, broker reason `nonce expired` |
| A4 | **Generation invalidation** | **PASS** | [`matrix-run1-abdefghi.txt`](./matrix-run1-abdefghi.txt) case f — HTTP 409, `instance generation changed` |
| A5 | **Non-leaked wrong-instance case** — B cannot read A's nonce; B claiming A's UUID gets only B | **PASS** | same file, cases g (guest API 404) and h (HTTP 200 resolving **B**) |
| A6 | Second redemption rejected | PASS | case b — HTTP 409 |
| A7 | Nonce for a deleted instance rejected | PASS | [`case-e-deleted-instance.txt`](./case-e-deleted-instance.txt) — HTTP 409, `attestor: instance not found` |
| A8 | **No nonce value in logs or evidence** | **PASS** | [`secret-scan.txt`](./secret-scan.txt) — executed scan over every file in this directory, 0 hits |
| M1 | **Unused leaked nonce is a bearer credential** | **MEASURED — go/no-go input** | [`matrix-run1-abdefghi.txt`](./matrix-run1-abdefghi.txt) case i — B redeemed A's leaked nonce and received **A's** identity, HTTP 200. See [§ Bearer-token risk](#bearer-token-risk) |
| C1 | Config keys cleared everywhere, throwaways deleted, guests A and B still running, one attested agent, host untouched | PASS | [`cleanup-final-state.txt`](./cleanup-final-state.txt) |
| **P1** | **Hardened binary deployed** — `c534af07…a741` verified from inside the container | **PASS** | [`postfix-01-redeploy.txt`](./postfix-01-redeploy.txt) |
| **P2** | **No insecure startup** — the process refuses to run with a missing, absent or short operator token, and no message contains token text | **PASS** | [`postfix-02-startup-refusals.txt`](./postfix-02-startup-refusals.txt) — four verbatim refusals, exit 1, nothing bound on 8443 |
| **P3** | **Mint authentication** — missing and wrong token both 401 with byte-identical bodies; no Incus read on either | **PASS** | [`postfix-03-mint-auth.txt`](./postfix-03-mint-auth.txt) — same body digest `3341bff0…cb31`, log shows `instance_uuid:""` on every 401 |
| **P4** | **`ttl_seconds` is real and bounded** — honoured exactly, out-of-range and non-positive refused with 400 | **PASS** | [`postfix-04-ttl-and-strict-decoders.txt`](./postfix-04-ttl-and-strict-decoders.txt) |
| **P5** | **Both decoders strict** — an unknown mint field is 400; a caller-supplied `instance_uuid` on redeem is 400 | **PASS** | same file — and the refusal does not burn the nonce |
| **P6** | **Expired unredeemed key is withdrawn** — the reaper clears `user.spiffe-bootstrap` with nobody redeeming, closing F2 | **PASS** | [`postfix-05-reaper.txt`](./postfix-05-reaper.txt) — `expired nonce withdrawn` naming nonce ID and instance UUID |
| **P7** | **Acceptance path re-proven post-hardening** — positive redemption, replay 409, three concurrent rounds with exactly one success each | **PASS** | [`postfix-06-acceptance-path.txt`](./postfix-06-acceptance-path.txt) |
| **P8** | **Hardened harness reaches a real verdict on every case** | **PASS** | [`postfix-07-harness-run.txt`](./postfix-07-harness-run.txt) — 8 PASS, 0 FAIL, **0 ERROR**, 1 MEASURED, exit 0 |
| **P9** | **Close-out** — keys clear, throwaway deleted, guests and broker running, one attested agent, zero entries, host untouched | **PASS** | [`postfix-08-cleanup-final-state.txt`](./postfix-08-cleanup-final-state.txt) |
| **P10** | **Secret scan over the whole directory, including the new transcripts** | **PASS** | [`postfix-09-secret-scan.txt`](./postfix-09-secret-scan.txt) — 0 hits, live positive control for both a nonce secret and the operator token |

**H7 is proven.** A guest is securely and uniquely bound to its Incus instance through
`/dev/incus/sock` and `user.spiffe-bootstrap`, with single use enforced by one atomic
compare-and-set, expiry enforced server-side, and the binding invalidated by a generation change.
The one documented weakness — an unused nonce is a bearer token — behaved exactly as the plan
predicted and is recorded below rather than treated as a defect.

## Deployment

### Topology

| Element | Value |
|---|---|
| Broker container | `spike-broker`, project `default`, `images:debian/13` container |
| Broker address | `10.55.156.44:8443` on `incusbr0`, listener `[::]:8443` |
| Advertised redeem URL | `https://10.55.156.44:8443/v1alpha1/redeem` |
| State volume | custom volume `spike-broker-state` on pool `local`, mounted at `/state` |
| Binary | `/usr/local/bin/incus-spiffe-broker`, SHA-256 `40e3c1bf2be5aba9822fa38b97a7f47666b38384bd87aafce697a040f10d8c08` (identical operator-side and in-container). **Superseded 2026-08-17 05:00 UTC:** the deployed binary is now `c534af07c95ef333b1a09dabb75367c6f66ab5cc01b1b178dc6f81ee89afa741`; see [§ Post-hardening re-verification](#post-hardening-re-verification-2026-08-17). |
| Supervision | systemd unit `incus-spiffe-broker.service`, `EnvironmentFile=/state/broker.env`, `Restart=no` |
| Guests | `spike-guest-a` `10.55.156.150` (VM, `volatile.uuid` `a955ca30-a0dc-4087-a369-37d53d389c5a`), `spike-guest-b` `10.55.156.75` (VM, `a4fec3ea-d4aa-4e6c-94c6-8295cee62338`), both project `spike-spiffe`, both with `incus-agent` running |

The broker was placed in project `default` deliberately: it must reach the Incus API endpoint
`https://147.135.105.83:8443` **and** the guests' bridge, while the credentials it carries are
confined to `spike-spiffe`. The container itself therefore holds no privilege in the project it
writes to beyond what those two P5 certificates grant.

### Sanitized configuration

**Superseded 2026-08-17.** The block below is the configuration of the pre-hardening run and is
kept because the transcripts of that run were captured against it. The current file has six more
settings — `MINT_TOKEN_FILE`, `MAX_NONCE_TTL`, `REAP_INTERVAL`, `REAP_TIMEOUT`, `REAP_GRACE` — and is
quoted verbatim in [`postfix-08-cleanup-final-state.txt`](./postfix-08-cleanup-final-state.txt).

Verbatim `/state/broker.env` as it stood for the original run (paths only; no secret value is
stored in it):

```
INCUS_SPIFFE_BROKER_LISTEN=:8443
INCUS_SPIFFE_BROKER_TLS_CERT=/state/tls/broker.crt
INCUS_SPIFFE_BROKER_TLS_KEY=/state/tls/broker.key
INCUS_SPIFFE_BROKER_ADVERTISE_URL=https://10.55.156.44:8443
INCUS_SPIFFE_BROKER_INCUS_URL=https://147.135.105.83:8443
INCUS_SPIFFE_BROKER_INCUS_SERVER_FINGERPRINT=822b00ed474a2574d43223cbf34919b76a64946e145ec246aa4ae2e43318afdd
INCUS_SPIFFE_BROKER_ATTESTOR_CERT=/state/incus/attestor.crt
INCUS_SPIFFE_BROKER_ATTESTOR_KEY=/state/incus/attestor.key
INCUS_SPIFFE_BROKER_BOOTSTRAP_CERT=/state/incus/bootstrap.crt
INCUS_SPIFFE_BROKER_BOOTSTRAP_KEY=/state/incus/bootstrap.key
INCUS_SPIFFE_BROKER_PROJECT=spike-spiffe
INCUS_SPIFFE_BROKER_NONCE_TTL=10m
INCUS_SPIFFE_BROKER_REQUEST_TIMEOUT=10s
```

Startup line of that run, which is what proves the port is actually held rather than merely
announced (**superseded**: the current line also carries `max_nonce_ttl`, `reap_interval`,
`reap_timeout` and `reap_grace`):

```json
{"msg":"incus-spiffe-broker listening","listen_address":"[::]:8443",
 "redeem_url":"https://10.55.156.44:8443/v1alpha1/redeem",
 "tls_fingerprint":"7cedc92f3e349063cfd060bbe8be4da00dcab4b12b164d765ca926b05147ab93",
 "incus_url":"https://147.135.105.83:8443","project":"spike-spiffe",
 "nonce_ttl":"10m0s","request_timeout":"10s"}
```

`ss -ltnp` confirmed `LISTEN *:8443 users:(("incus-spiffe-br",pid=481))`.

### TLS

**Decision: the certificate was issued by the P1 spike root CA, not self-signed.** The CA lives on
the existing custom volume `spike-ca-state`, which is mounted at `/ca` in `spike-p3-stage`; the key
pair and the signature were produced inside that container so the broker private key never touched
the operator workstation, and the scratch directory was deleted afterwards. Choosing the real CA
means the guests validated a chain (`--cacert`) rather than trusting a leaf they had just fetched,
so the run proves chain validation as well as pinning.

| Field | Value |
|---|---|
| Subject | `CN=spike-broker` |
| Issuer | `O=incusos-spire spike, CN=spike root CA` |
| Serial | `598B7D5DDAB39F6C59C41DB9E69EBB7072C85FDD` |
| Validity | `Aug 17 03:51:44 2026 GMT` → `Sep 16 03:51:44 2026 GMT` |
| SAN | `DNS:spike-broker, DNS:localhost, IP:10.55.156.44, IP:127.0.0.1` |
| Key usage | critical: Digital Signature, Key Encipherment; EKU: TLS Web Server Authentication |
| **Leaf SHA-256 (the value guests pin)** | **`7cedc92f3e349063cfd060bbe8be4da00dcab4b12b164d765ca926b05147ab93`** |
| SPKI pin (`curl --pinnedpubkey`) | `sha256//VgsjkxXQUOpcDDf3ME0k558xOPa4eQlShWxr+H0l/DA=` |
| Spike root CA SHA-256 | `b057b3f2023413fdec184c6262e1de4d760d0943ffd677762adfb1a7510db1eb` |

The broker derives the advertised fingerprint from the loaded certificate rather than from
configuration, and the value it logged is byte-identical to the one computed independently from the
PEM — an operator cannot advertise a stale pin.

### Credential split

| File in the broker | P5 identity | Certificate SHA-256 | Rights |
|---|---|---|---|
| `/state/incus/attestor.{crt,key}` | `CN=spike-attestor-ro, O=spike-incusos-spire` | `6ebaf5eb4cc9e003acb6a98ef7cdd24b1d2d7a00ef59f5fb9b654e3fa634db80` | read-only, project-confined to `spike-spiffe`; resolves a UUID to an instance record |
| `/state/incus/bootstrap.{crt,key}` | `CN=spike-bootstrap-writer, O=spike-incusos-spire` | `afd4f608e0f0e8aabce5e42a6dba33ca7ff3b76defad3f0e287f46c5136d9d84` | write-only, denied all reads; writes and clears `user.spiffe-bootstrap` |

`options.validate` refuses to start if both flags point at the same file, so the split cannot be
collapsed by a configuration slip. Full record: [`deployment.txt`](./deployment.txt).

### How the matrix was driven

The Incus client runs on a macOS workstation that has no route to `incusbr0`, while the harness
needs both `incus` and HTTP access to the broker. A throwaway container `spike-p8-operator`
(project `default`) was therefore used as the operator host: it received `jq`, `curl`, `openssl`,
`incus-client`, and a copy of the existing operator Incus client certificate — no new trust was
added to the Incus server. It was **deleted** at the end of the run because it held that key.

## Lifecycle matrix

`spike/p8/lifecycle-matrix.sh` was run unmodified with `STRICT_STATUS=1`, so an unexpected status
code fails the run rather than producing a note. Cases a, b, d, f, g, h, i ran in one pass; cases c
and e needed a different driver for reasons stated in their subsections. The script was **not
edited** at any point.

### Case a — positive redemption · **HTTP 201 then HTTP 200**

`operator-mint.sh` minted for `a955ca30-a0dc-4087-a369-37d53d389c5a`; the mint answer was
`201` and carried **no** `nonce`, `secret`, `token` or `password` field — the script asserts this
and would have exited `20` otherwise.

Host-side view of the written key ([`positive-02-host-key-set.txt`](./positive-02-host-key-set.txt)),
value withheld:

```
visible user.* keys on the instance:
  user.spiffe-bootstrap
payload field names:
  broker_fingerprint
  broker_url
  nonce
  nonce_id
payload field count: 4
nonce_id:            72c9cd50d98a862105f5d6e08552916a
broker_url:          https://10.55.156.44:8443/v1alpha1/redeem
broker_fingerprint:  7cedc92f3e349063cfd060bbe8be4da00dcab4b12b164d765ca926b05147ab93
nonce field:         type=string length=64 value=<withheld: Appendix D>
```

Exactly the four documented fields, and the only key in the instance's `user.*` namespace.

`guest-bootstrap.sh` inside `spike-guest-a` then read the key through its own
`/dev/incus/sock` (`GET /1.0/config/user.spiffe-bootstrap -> HTTP 200`), compared the broker leaf
digest against `broker_fingerprint`, pinned the SPKI, validated the chain against the spike CA, and
posted the redemption:

```
redeem: HTTP 200
verdict: GRANTED 200
  resolved_instance_uuid=a955ca30-a0dc-4087-a369-37d53d389c5a
  resolved_instance_name=spike-guest-a
  resolved_generation=a955ca30-a0dc-4087-a369-37d53d389c5a
  project=spike-spiffe
  selectors=incus:uuid:a955ca30-a0dc-4087-a369-37d53d389c5a,
            incus:generation:a955ca30-a0dc-4087-a369-37d53d389c5a,
            incus:project:spike-spiffe,
            incus:type:virtual-machine,
            incus:name:spike-guest-a,
            incus:image:9eb18b1a93682960e9e190cd818284ad4bcaf1740be9a435630a3b1dc60acee7
```

Those are the six frozen P7 selectors, for guest A's UUID. Immediately afterwards the key was gone
from both sides ([`positive-04-key-cleared.txt`](./positive-04-key-cleared.txt)): the host shows no
`user.*` key at all, and the guest's own socket answers `HTTP 404` with a visible-key list of `[]`.

### Case b — second redemption of the same nonce · **HTTP 409**

Nonce `0b4401b37bac469b259107aa49839ddc`: first redemption `200`, immediate replay of the identical
payload `409`, broker reason `nonce: nonce already used`.

### Case c — expired nonce · **HTTP 409**

**Superseded 2026-08-17.** The paragraph below described the pre-hardening binary. `ttl_seconds` is
now a real, bounded mint field and the workaround it describes is no longer needed; the current
behaviour is in [§ The `ttl_seconds` contract](#the-ttl_seconds-contract-and-the-strict-decoders).
The observation the case was run to make — that expiry is enforced server-side while the key stays
readable — still holds, and the second half of it is what the reaper now addresses.

Driven separately. **The broker has no `ttl_seconds` field**: `mintRequest` in
`cmd/incus-spiffe-broker/service.go` is `{instance_uuid, project}` and `decodeRequest` does not set
`DisallowUnknownFields`, so the harness's `MINT_TTL_SECONDS` / `SHORT_TTL_SECONDS` is accepted by
the wire and silently discarded. The TTL was therefore changed where it actually lives: the service
was restarted with `INCUS_SPIFFE_BROKER_NONCE_TTL=5s` (`"nonce_ttl":"5s"` in the startup line),
case c was run with `EXPIRY_WAIT_SECONDS=12`, and the TTL was restored to `10m` afterwards.

```
minted nonce_id=ec5f93034716369e5755ccc6974243e9 expires_at=2026-08-17T03:59:29.221415042Z
--- waiting 12s for the nonce to expire
socket_read: GET /1.0/config/user.spiffe-bootstrap -> HTTP 200      ← the key is STILL readable
redeem: HTTP 409
broker reason: "nonce: consume nonce ec5f…: nonce: nonce expired: id ec5f…"
```

Note the third line: expiry is enforced entirely server-side. See finding F2.

### Case d — two concurrent redemptions · **exactly one HTTP 200, the other HTTP 409**

The harness case d passed (`200/409`), but its two redemptions are separate `incus exec`
invocations and are therefore a process spawn apart. Because case d is the acceptance criterion for
atomic single use, a tighter probe was run as well
([`case-d-strict-concurrency.txt`](./case-d-strict-concurrency.txt)): two workers inside
`spike-guest-a` spin on the same absolute wall-clock second and then POST, so the requests leave the
guest microseconds apart. The nonce secret is read from the 0600 payload by `jq` into a 0600 body
file and handed to `curl` as `--data @file`, never through `argv`.

| Round | Nonce ID | Worker 1 sent | Worker 2 sent | Δ | Statuses | Verdict |
|---|---|---|---|---|---|---|
| 1 | `fc9950ac2579e21d914edcc9a1ba5c23` | `03:58:38.002523311` | `03:58:38.002209401` | 314 µs | `200` / `409` | exactly one success |
| 2 | `68f73897ff605b4607c2aaadbdbe45b7` | `03:58:44.002060962` | `03:58:44.001442081` | 619 µs | `409` / `200` | exactly one success |
| 3 | `cf533f331ac17377f28724e9d0e0ed19` | `03:58:50.001866843` | `03:58:50.002476934` | 610 µs | `200` / `409` | exactly one success |

The winner alternated between the two workers across rounds, which is what a genuine race looks
like rather than a fixed ordering. **Two successes never occurred.** The broker log also shows the
loser's `409 nonce already used` landing *before* the winner's `bootstrap key cleared` line in
rounds 1–3 — direct evidence of the plan's required ordering: `used=true` is committed first, and
only then is the instance config key cleared, so a crash in between leaves a consumed value rather
than a live credential.

### Case e — nonce for a deleted instance · **HTTP 409**

Driven by hand. The harness attempt failed for an environmental reason, stated plainly: the stock
`images:debian/13` rootfs has no `jq`, `guest-bootstrap.sh` requires it, and the script has no
package-install hook, so case e aborted with
`setup: spike-guest-tmp could not read its bootstrap key (exit 2)` in
[`matrix-run1-abdefghi.txt`](./matrix-run1-abdefghi.txt). Rather than edit the harness, the same
sequence was executed manually with `jq` installed
([`case-e-deleted-instance.txt`](./case-e-deleted-instance.txt)):

1. throwaway container `spike-guest-tmp`, `volatile.uuid` `d124f996-a01f-406d-aa21-4d4e7fdc7777`;
2. mint → `201`, `nonce_id=1c2b7f928923855f61aed718fbd4b21d`;
3. the throwaway read its own key through its own socket and staged it (payload SHA-256
   `d40b1401041caa1d1189c7c4e911b8e633085e55c12ae94622f28c4774a34eb8`);
4. the payload was piped guest-to-guest into `spike-guest-b` — `incus file pull … - | incus file
   push - …`, so it never touched the operator disk; the digest in B matched;
5. `spike-guest-tmp` deleted;
6. B redeemed the still-unused nonce → **`HTTP 409`**, broker reason `attestor: instance not found`.

### Case f — generation change · **HTTP 409**

`spike-guest-a` was snapshotted and restored, which P6 proved always installs a fresh
`volatile.uuid.generation`:

```
generation before: a955ca30-a0dc-4087-a369-37d53d389c5a
generation after:  d79b19ff-549c-4809-be8a-94822a41f506
redeem: HTTP 409
broker reason: "nonce: instance generation changed: nonce 5f2b0470… was minted for an earlier
                generation of a955ca30-a0dc-4087-a369-37d53d389c5a"
```

The pre-restore payload was stashed in guest B and piped back afterwards, because the restore
reverts A's filesystem. Guest A's generation is **permanently** `d79b19ff-549c-4809-be8a-94822a41f506`
from this point on; its `volatile.uuid` is unchanged.

### Case g — guest B cannot read A's nonce · **guest API HTTP 404**

With a live, unused nonce set on A (payload SHA-256
`d36e0f66b34f705552c1ba1e859bba75f4e5a4b1b8c41f60ba78019c42a108d4`), B's own `/dev/incus/sock`
answered `GET /1.0/config/user.spiffe-bootstrap -> HTTP 404`. Delivery is per-instance, exactly as
`GUEST_SOCK_BRIEF.md` §3 predicts from the Incus 7.3 source. The harness compares digests, not
values, so a leak would have been caught without printing anything.

### Case h — B claims A's UUID with B's own nonce · **HTTP 200 resolving B**

**Superseded 2026-08-17.** The claimed `instance_uuid` is now **refused with HTTP 400** by the
strict redeem decoder rather than accepted and discarded. B still obtains only B's identity, from
its own unclaimed nonce, so the security property below is unchanged and the answer is stronger.
See [§ The `ttl_seconds` contract](#the-ttl_seconds-contract-and-the-strict-decoders) and
[`postfix-06-acceptance-path.txt`](./postfix-06-acceptance-path.txt).

```
redeem: POST … nonce_id=a5aa7b11c436d6eba25da55979a8b9b8 claimed_instance_uuid=a955ca30-…(A)
redeem: HTTP 200
  resolved_instance_uuid=a4fec3ea-d4aa-4e6c-94c6-8295cee62338   ← B
  resolved_instance_name=spike-guest-b
  selectors=incus:uuid:a4fec3ea-…,incus:generation:a4fec3ea-…,incus:project:spike-spiffe,
            incus:type:virtual-machine,incus:name:spike-guest-b,incus:image:9eb18b1a…
```

The claimed UUID was discarded. **B never obtained any part of A's identity** — not the UUID, not
the name, not the generation. This is the security property the plan asks for: the request field is
untrusted input, and the binding is resolved only from the server-side nonce record.

### Case i — leaked unused A nonce redeemed from B · **HTTP 200 granting A's identity (MEASURED)**

See [§ Bearer-token risk](#bearer-token-risk).

### Supplementary measurement — a rejected redemption may or may not burn the nonce

Not a plan case; measured because it decides whether a guest may retry
([`supplementary-burn-semantics.txt`](./supplementary-burn-semantics.txt)). Using a throwaway
container `spike-p8-gen` and nonce `52a26ffd0180591b9ca2d48b946f837f`:

| Attempt | Status | Broker reason |
|---|---|---|
| 1, after a generation change | `409` | `nonce: instance generation changed` |
| 2, identical payload | `409` | `nonce: nonce already used` |

So a generation mismatch **consumes** the nonce (the check happens after the atomic
`ConsumeOnce`), whereas case e's `attestor: instance not found` is raised *before* the consume and
leaves the nonce unconsumed. Both fail closed, but only one is retryable. See finding F3.

## Bearer-token risk

Case i is the plan's explicit measurement, not a failure. A nonce was minted for guest A
(`492f308af40d3d50c73d1076a54b508d`), A read it through its own socket, the payload was piped into
guest B **while still unused**, and B redeemed it. Result, verbatim:

```
redeem: HTTP 200
verdict: GRANTED 200
  resolved_instance_uuid=a955ca30-a0dc-4087-a369-37d53d389c5a     ← A
  resolved_instance_name=spike-guest-a                            ← A
  resolved_generation=d79b19ff-549c-4809-be8a-94822a41f506        ← A
  selectors=incus:uuid:a955ca30-…,incus:generation:d79b19ff-…,incus:project:spike-spiffe,
            incus:type:virtual-machine,incus:name:spike-guest-a,incus:image:9eb18b1a…
```

Guest B received **guest A's complete identity**: A's UUID, A's name, A's generation, and the full
six-selector set that a P9 exchange SVID would be minted against. The broker behaved correctly at
every step — it resolved the binding server-side and never believed a caller claim — and it still
issued A's identity to B, because possession of the secret is the only evidence the protocol
carries.

**The security consequence, stated plainly.** Between the moment the broker writes
`user.spiffe-bootstrap` and the moment it is redeemed, the value is an unauthenticated bearer token
for the target instance's SPIFFE identity, and nothing in the current design binds it to the
calling VM's transport. `GUEST_SOCK_BRIEF.md` §6 explains why that cannot be fixed on the guest
side alone: a guest cannot read `volatile.uuid` or `volatile.uuid.generation` through
`/dev/incus/sock`, so it has no material with which to prove who it is, and possession is all it
can offer. The exposure is real but narrow — the value is readable only by guest root (§7 of the
brief: containers enforce a peer-UID check, VMs a mode-0600 socket), it is single-use, and it dies
at the TTL — so the practical attack is a root compromise of the target guest, an operator or
backup process that copies instance configuration, or an Incus API reader with `user.*` visibility.
Anyone in that set can steal the identity of the guest the nonce was minted for, silently, and the
theft is indistinguishable from a legitimate redemption. **This is a go/no-go input for P9**: if
the exchange SVID that P9 hands back is worth more than the nonce that bought it, the prototype
needs a second caller-binding factor (candidates: a guest-generated key whose public half the
broker learns out of band before the nonce is written, a vsock/CID check, or a short TTL measured
in seconds combined with a first-boot-only window). None of those are built, and the spike does not
claim the problem is solved.

## Findings for the architecture

**F1 — CLOSED 2026-08-17 (was: the mint API has no TTL parameter, but the harness documentation
says it does).** Both halves of the suggested fix were taken: `ttl_seconds` is now a real optional
mint field bounded by `-max-nonce-ttl` and refused rather than clamped, and both decoders reject
unknown fields. The guest endpoint did **not** keep ignoring unknown fields as this finding
proposed — it accepts the four payload fields and refuses everything else, including
`instance_uuid`, which is a stricter answer than the finding asked for and does not break the
verbatim forward that case h depends on. Proof:
[`postfix-04-ttl-and-strict-decoders.txt`](./postfix-04-ttl-and-strict-decoders.txt). Original text:

**F1 — the mint API has no TTL parameter, but the harness documentation says it does.**
`spike/p8/README.md` documents `ttl_seconds` as an optional mint field and both scripts send it;
`mintRequest` does not have it and `decodeRequest` does not reject unknown fields, so it is
accepted and dropped. Nothing warns. Any operator following the harness README would believe a
short-lived nonce had been issued while the broker's configured `10m` applied. Either add the field
with an upper bound, or reject unknown fields on the operator endpoint so a stale caller fails
loudly. The guest endpoint must keep ignoring unknown fields — that is what lets a guest forward
the payload verbatim, and case h depends on it.

**F2 — CLOSED 2026-08-17 (was: nothing ever clears an unredeemed `user.spiffe-bootstrap`).** The
service now has the sweeper this finding asked for, over the write-only credential it already
holds, with a grace window so an expired nonce keeps answering 409 rather than 401 for a caller who
is merely late. Proven live in [`postfix-05-reaper.txt`](./postfix-05-reaper.txt): a nonce nobody
redeemed had its key withdrawn 15 seconds after expiry, logged as `expired nonce withdrawn` with
the nonce ID and instance UUID. Original text:

**F2 — nothing ever clears an unredeemed `user.spiffe-bootstrap`.** In case c the nonce expired and
the guest could still read the key (`HTTP 200`); only the redemption failed. The broker clears the
key on the success path, and the P8 harness clears it in its cleanup trap, but the service itself
has no reaper: a nonce that is minted and never redeemed leaves a dead payload on the instance
configuration indefinitely, readable by guest root and by every Incus reader with `user.*`
visibility. In the spike this is untidy; in production it is a slowly accumulating pile of expired
bearer tokens whose only defence is that they are expired. A sweeper that clears the key when the
record expires is the obvious fix, and it needs the write-only credential the broker already holds.

**F3 — failure modes differ in whether they burn the nonce, and that difference is invisible to the
caller.** Measured above: a generation change consumes the nonce, a not-found instance does not,
and both answer `409 conflict` with byte-identical bodies. That is deliberate for confidentiality —
a caller cannot enumerate nonce state — but it means a guest cannot tell "retry is pointless" from
"retry may work once the API recovers". P9's bootstrap logic should treat every `409` as terminal
and require a fresh nonce, because assuming otherwise is unsafe in exactly the case where it
matters.

**F4 — the deleted-instance rejection is a resolution failure, not a binding check.** The `409` in
case e came from `attestor: instance not found`, i.e. the same code path P7 showed is
indistinguishable from a trusted-but-under-privileged credential (P7 finding R7). If the read-only
credential ever loses its project grant, every redemption in the fleet fails with the message that
also means "your instance was deleted". This is P7's R7 resurfacing one layer up, and it argues for
distinguishing authorization failure from empty-result at the adapter boundary.

**F5 — nonce state is in memory only, so a broker restart silently invalidates every outstanding
nonce.** `internal/nonce/memory` is the only store built; `internal/nonce/sqlite` is deliberately
absent. Restarting the service for case c dropped all live records. Nothing tells a guest holding a
written-but-unredeemable payload that this happened — it gets `401 unauthorized` (unknown nonce
ID), which is the same answer as a forged ID. For the spike this is correct and cheap; for the
product, a broker restart during a fleet-wide boot storm would produce a wave of `401`s that look
like an attack. Recorded, not fixed, per Appendix C.

**F6 — no upstream behaviour contradicted the documentation this time.** Every guest-socket
prediction in `GUEST_SOCK_BRIEF.md` held on live hardware: raw `application/octet-stream` value,
`404` for a missing key, `user.*`-only visibility, per-instance delivery, a live update visible
without a restart, and a VM that needs `incus-agent` for `/dev/incus/sock` to exist. Earlier phases
found five upstream contradictions; P8 found none. The one non-obvious observation is positive:
the VM socket is mode `0600` root-only while the container socket is `0666` and relies on the
server-side peer-UID check — different mechanisms, same outcome, and both were seen.

## Post-hardening re-verification (2026-08-17)

Everything above this heading describes the run of 2026-08-17 03:50–04:04 UTC. This section
describes a second run, 04:45–05:04 UTC on the same host, against a different binary. Nothing above
was rewritten; the claims that the new binary made untrue are annotated in place as **Superseded**.

### Why there was a second run

The first run passed and H7 was proven, and then an independent security review of the same code
found nine defects, three of them High. That review is
[`SECURITY_FINDINGS.md`](./SECURITY_FINDINGS.md) and it is not restated here. Six of the nine were
assigned to spike code or spike harness and have been fixed; the deployed binary was therefore
stale and, more importantly, its behaviour had changed in ways that made parts of the evidence
above wrong rather than merely old. This section brings the evidence back into line with the code
at commit `ade77d8`.

| Finding | Class | What changed in the binary or harness |
|---|---|---|
| **SEC-002** | High | `POST /v1alpha1/nonce` now requires `Authorization: Bearer <token>`. The token is read once at startup from `-mint-token-file`, must be at least 32 characters, and only its SHA-256 is retained. There is no unauthenticated mode. `POST /v1alpha1/redeem` stays unauthenticated by design — the nonce *is* the guest's credential, and requiring a second one would need the very channel this exchange exists to establish. |
| **SEC-008** | Low | `ttl_seconds` is a real optional mint field, bounded by `-max-nonce-ttl` and refused rather than clamped. |
| **SEC-008** (decoders) | Low | Both decoders now set `DisallowUnknownFields`. Mint accepts `instance_uuid`, `project`, `ttl_seconds`; redeem accepts the four bootstrap-payload fields and refuses everything else, `instance_uuid` included. |
| **SEC-004** | Medium | A mint whose caller went away is withdrawn on a detached bounded context: clear the key, delete the record, logged `unacknowledged mint withdrawn`. |
| **SEC-002** (pruning half) / **F2** | High | A reaper sweeps expired, never-consumed records: re-resolve the UUID through the read path (names are reusable, P6), clear the key, delete the record, logged `expired nonce withdrawn`. New flags `-reap-interval`, `-reap-timeout`, `-reap-grace`. |
| **SEC-006, SEC-007** | Medium | `spike/p8/*.sh` now distinguishes PASS / FAIL / ERROR / MEASURED, never counts a dependency failure as a pass, has a guest dependency preflight with an opt-in installer, verifies the bootstrap key is gone during cleanup, and exits 3 on incomplete cleanup. |

**SEC-009 and SEC-001 were deliberately not fixed in code**, and this run does not claim otherwise.
SEC-009 is the secret-carrier gap: `spike-attestor-ro` can read the full configuration of every
instance in the project, including a live `user.spiffe-bootstrap`, so the read-only credential can
steal a nonce before its guest redeems it. No endpoint check in this binary can close that; it is
the same fact the [§ Bearer-token risk](#bearer-token-risk) section reaches from the guest side, and
it is a carrier-design decision. SEC-001 is credential co-location: the network listener holds both
the trusted reader and the project-wide config-write credential, and the production rule
[`SECURITY_FINDINGS.md`](./SECURITY_FINDINGS.md) states — the listener must never possess the raw
writer credential — is a deployment split this spike does not make. Both remain open, by decision.

### Redeploy

Full record: [`postfix-01-redeploy.txt`](./postfix-01-redeploy.txt).

The service was stopped, the binary replaced, and the digest recomputed **inside the container**:

```
c534af07c95ef333b1a09dabb75367c6f66ab5cc01b1b178dc6f81ee89afa741  /usr/local/bin/incus-spiffe-broker
```

byte-identical to the operator-side digest of `/tmp/incus-spiffe-broker-linux`, and different from
the `40e3c1bf…` that had been serving.

An operator bearer token was generated **inside the broker container** — 64 hex characters from
`/dev/urandom`, written straight to `/state/auth/mint-token` under `umask 077`, never echoed, never
placed in `argv`, never exported. Its digest is `b611396f…a172`; the value appears nowhere. The unit
was left as it was and `/state/broker.env` gained six settings. The service restarted and bound the
port again:

```json
{"msg":"incus-spiffe-broker listening","listen_address":"[::]:8443",
 "redeem_url":"https://10.55.156.44:8443/v1alpha1/redeem",
 "tls_fingerprint":"7cedc92f3e349063cfd060bbe8be4da00dcab4b12b164d765ca926b05147ab93",
 "incus_url":"https://147.135.105.83:8443","project":"spike-spiffe",
 "nonce_ttl":"10m0s","max_nonce_ttl":"10m0s","reap_interval":"1m0s","reap_timeout":"30s",
 "reap_grace":"2m0s","request_timeout":"10s"}
{"msg":"expired nonce reaper started","operation":"reap","interval":"1m0s","timeout":"30s","grace":"2m0s"}
```

The TLS leaf is unchanged, so every pin recorded in [§ TLS](#tls) still holds and guests need no
new trust material.

### Startup refuses an insecure configuration

Full record: [`postfix-02-startup-refusals.txt`](./postfix-02-startup-refusals.txt). Four attempts,
each with the complete working configuration and only the token varied. All four exited `1`, and
`ss -ltn` afterwards showed **nothing bound on 8443** — these failures happen before the listener.

```
(a) no -mint-token-file
    "invalid configuration: -mint-token-file is required"

(b) a 16-character token, environment form
    "operator mint token in /state/auth/short-token is 16 characters; -mint-token-file requires at least 32"

(c) the same, flag form
    "operator mint token in /state/auth/short-token is 16 characters; -mint-token-file requires at least 32"

(d) a token file that does not exist
    "read operator mint token: open /state/auth/absent: no such file or directory"
```

The length message names the path and the count and never the value. That was checked rather than
asserted: the three refusals were captured to a file inside the container and searched with
`grep -F -f`, needle read from the token file so it never reached `argv`. Zero matches for the
short token, zero for the real one, and a planted copy matched — so the search worked.

### Mint authentication

Full record: [`postfix-03-mint-auth.txt`](./postfix-03-mint-auth.txt), driven from `spike-probe` on
`incusbr0` with the token spliced into a mode-0600 `curl --config` file.

| Credential presented | Status | Body | Body SHA-256 |
|---|---|---|---|
| none | **401** | `{"error":"unauthorized"}` | `3341bff062d83e3afeb943f83bbb079f5b45cc050e796ec282dde50b5906cb31` |
| 64 zeros — right length, wrong value | **401** | `{"error":"unauthorized"}` | `3341bff062d83e3afeb943f83bbb079f5b45cc050e796ec282dde50b5906cb31` |
| the operator token | **201** | binding metadata, no secret field | — |

The two 401 bodies are byte-identical and both carry
`WWW-Authenticate: Bearer realm="incus-spiffe-broker"`. A caller cannot tell "you sent nothing" from
"you sent the wrong thing", and the log distinguishes them by neither — it records the peer address.

**The check runs before the Incus read**, which is the point of it, and that was proven
differentially rather than by reading the source. A UUID that resolves to no instance was minted
for twice, once without a token and once with:

```
unauthenticated:  401 {"error":"unauthorized"}
  log: instance_uuid:""            ← the body was never decoded, so nothing was ever resolved
authenticated:    409 {"error":"conflict"}
  log: instance_uuid:"00000000-0000-4000-8000-000000000000" reason:"attestor: instance not found"
       ← the read-only credential actually reached the Incus API and came back empty
```

Same body, same endpoint, seconds apart; the only difference is the token, and the only request
that touched Incus is the one that presented it. The check also precedes decoding: a body that is
not JSON answers `401` without a token and `400 invalid_request` with one.

### The `ttl_seconds` contract and the strict decoders

Full record: [`postfix-04-ttl-and-strict-decoders.txt`](./postfix-04-ttl-and-strict-decoders.txt).
Broker settings for this section: `-nonce-ttl 10m`, `-max-nonce-ttl 10m`, so the accepted band is
1–600 seconds.

| Request | Status | Applied lifetime |
|---|---|---|
| `ttl_seconds` omitted | 201 | `04:54:25.501 → 05:04:25.501` = **10m0s**, the process default |
| `ttl_seconds: 5` | 201 | `04:54:43.494 → 04:54:48.494` = **5s exactly**, not clamped up |
| `ttl_seconds: 601` | **400** | refused, not clamped down |
| `ttl_seconds: 0` | **400** | refused |
| `ttl_seconds: -5` | **400** | refused |
| unknown field `ttl_secondz` | **400** | refused |
| unknown field `instance_name` | **400** | refused |
| redeem carrying `instance_uuid` | **400** | refused — `json: unknown field "instance_uuid"` |
| the same nonce, unclaimed | 200 | resolves A, six frozen selectors, key cleared |
| redeem after the 5s nonce lapsed | **409** | expiry still enforced server-side |

Every 400 body is byte-identical (`{"error":"invalid_request"}`,
`e7316a421dd2538cb55696b15062462d0689c695d94f454350935a6f2e3b44ef`): the broker names the class and
never the cause.

Two things are worth stating plainly. First, the five-second window really was five seconds — the
`expires_at` is the record of what applied, and the nonce genuinely stopped redeeming, verified by a
guest redemption twelve seconds later that answered `409`. Second, **case h's answer has changed**:
a caller-supplied `instance_uuid` used to be accepted and silently discarded, and is now refused
before anything is resolved. That is stricter, not weaker — an identity claim cannot decide a
binding if it cannot be stated at all — and it is not a denial of service, because the refused
nonce redeemed normally on the immediate follow-up without the claim.

### The reaper, and what closing F2 does and does not mean

Full record: [`postfix-05-reaper.txt`](./postfix-05-reaper.txt). Run with `-reap-interval 10s` and
`-reap-grace 10s` so the proof fits in a transcript; both were restored to `1m` and `2m` afterwards
and the restored values are in the final startup line.

A nonce was minted for `spike-guest-a` with `ttl_seconds: 10` and **never redeemed**:

```
04:56:20.365   nonce b05987faeb4b463fb622bdc91a1e0586 minted
04:56:31.365   expires_at — it stops being redeemable
04:56:33 / 38 / 43   host: user.spiffe-bootstrap still SET; the guest could still read it
04:56:41.365   expires_at + reap-grace: now withdrawable
04:56:46.729   {"msg":"expired nonce withdrawn","operation":"reap",
                "nonce_id":"b05987faeb4b463fb622bdc91a1e0586",
                "instance_uuid":"a955ca30-a0dc-4087-a369-37d53d389c5a",
                "instance_name":"spike-guest-a","expires_at":"04:56:31.365"}
04:56:49       host: GONE. Guest socket: GET /1.0/config/user.spiffe-bootstrap -> HTTP 404
```

No redemption of that nonce appears anywhere in the log, because none happened. This is exactly the
gap F2 named: in the original run the case-c payload sat readable on instance configuration after
expiry with nothing in the system to remove it.

What "closed" means here is worth being precise about, because the distinction is the same one
SEC-009 turns on. The reaper bounds how long a **dead** secret lingers in instance configuration. It
does not shorten the window in which a **live** nonce is a bearer credential, and it cannot: during
that window the value has to be readable, which is the whole mechanism. The grace window is also
deliberate rather than sloppy — withdrawing at `expires_at` would turn the documented `409` for an
expired nonce into a `401` for a nonce that never existed, and cost a late caller the difference
between "too late" and "wrong".

### The acceptance path, re-proven

Full record: [`postfix-06-acceptance-path.txt`](./postfix-06-acceptance-path.txt).

**Positive path.** Mint `201`, four payload fields on the instance and nothing else in `user.*`,
guest A read it through its own `/dev/incus/sock`, verified the leaf digest against
`broker_fingerprint`, pinned the SPKI, validated the chain against the spike CA, and redeemed:
`HTTP 200` with the six frozen selectors for A's UUID. The key was then gone from both the host and
the guest socket (`HTTP 404`).

**Replay.** The identical body a moment later: `409`, broker reason `nonce: nonce already used`.

**Concurrency**, the acceptance criterion for atomic single use. Two workers inside guest A spin on
the same absolute wall-clock second and then POST:

| Round | Nonce ID | Worker 1 sent | Worker 2 sent | Δ | Statuses |
|---|---|---|---|---|---|
| 1 | `506964f7452a0fdc2c28f94d73ae79a4` | `04:58:23.002132` | `04:58:23.001623` | 509 µs | `409` / `200` |
| 2 | `2a5fd302043f768f726e7075f46737d7` | `04:58:28.001886` | `04:58:28.001382` | 504 µs | `409` / `200` |
| 3 | `03a3c3f2e7254b6fb8a5e7dc5a19442e` | `04:58:33.001340` | `04:58:33.001845` | 505 µs | `200` / `409` |

Exactly one success every round, the winner moved between workers, and **two successes never
occurred**. The ordering the plan requires still holds in all three rounds: the loser's `409` is
logged before the winner's `bootstrap key cleared`, so `used=true` commits first and a crash between
the two leaves a consumed value rather than a live credential.

**Wrong-instance case h.** Guest B presented B's own nonce and claimed A's UUID: `HTTP 400`,
`json: unknown field "instance_uuid"`. The follow-up without the claim: `HTTP 200` resolving
**B** — B's UUID, B's name, B's generation, B's six selectors. B obtained no part of A's identity in
either answer.

### The hardened harness

Full record, including the preflight banner and the summary table:
[`postfix-07-harness-run.txt`](./postfix-07-harness-run.txt). `spike/p8/lifecycle-matrix.sh` was run
**unmodified** with `STRICT_STATUS=1` and `GUEST_INSTALL_DEPS=1`, from a throwaway operator
container on `incusbr0`.

| Case | Outcome | Detail |
|---|---|---|
| a | **PASS** | A redeemed its own nonce through `/dev/incus/sock`, `200`, `instance_uuid` = A |
| b | **PASS** | second redemption `409` |
| c | **PASS** | expired nonce `409` after an 8-second wait derived from the returned `expires_at` |
| d | **PASS** | exactly one of two concurrent redemptions succeeded (`409` / `200`) |
| e | **PASS** | nonce of the deleted `spike-guest-tmp` `409` |
| f | **PASS** | generation change `d79b19ff… → c32efc7b…` invalidated the nonce, `409` |
| g | **PASS** | B's socket refused the key with guest API `404` |
| h | **PASS** | the claimed UUID was **refused** (`400`) and B's own nonce still resolved only B |
| i | **MEASURED** | B redeemed A's leaked nonce and received A's identity, `200` — the recorded bearer-token risk |

`outcomes: 8 PASS, 0 FAIL, 0 ERROR, 1 MEASURED`, exit status `0`, and
`cleanup: complete — every step verified`.

**Every case reached a real verdict this time, and the one that could not last time is the reason
the harness was changed.** Case e died in the original run with a bare `exit 2` because stock
`images:debian/13` has no `jq`; it had to be repeated by hand. This time the preflight assessed the
disposable instance immediately after launching it, found `jq` missing, installed it because
`GUEST_INSTALL_DEPS=1` was given explicitly, re-checked, and the case ran to a real `409`.

Two cosmetic blemishes are reported rather than worked around, because neither changed a verdict.
The preflight banner prints the token path concatenated with itself
(`file /root/p8/mint-token/root/p8/mint-token`) in one display line, while the credential itself
resolved correctly — every mint in the run answered `201`. And each case opens with
`WARNING: could not clear user.spiffe-bootstrap on <guest>`, because the pre-case clear treats an
already-absent key as a failed unset; that is the safe direction to be wrong in, and the end-of-run
cleanup verified absence on both guests by reading the key back.

Case f changed guest A's generation again, as it must. It is now
`c32efc7b-f3d8-4637-9818-f8906c35543a`, and P9's `incus:generation:` selector for guest A must use
that value, not the `d79b19ff…` recorded earlier in this document.

### New transcripts

| File | What it records |
|---|---|
| [`postfix-01-redeploy.txt`](./postfix-01-redeploy.txt) | stop, push, in-container digest, token generation, new `broker.env`, restart, startup log, listener |
| [`postfix-02-startup-refusals.txt`](./postfix-02-startup-refusals.txt) | four insecure-configuration refusals, verbatim, plus the executed check that no token text is in them |
| [`postfix-03-mint-auth.txt`](./postfix-03-mint-auth.txt) | 401 / 401 / 201, identical body digests, and the differential proof that no Incus read happens on a 401 |
| [`postfix-04-ttl-and-strict-decoders.txt`](./postfix-04-ttl-and-strict-decoders.txt) | the `ttl_seconds` band, both strict decoders, and the expiry of a five-second nonce |
| [`postfix-05-reaper.txt`](./postfix-05-reaper.txt) | an unredeemed nonce's key withdrawn by the sweep, closing F2 |
| [`postfix-06-acceptance-path.txt`](./postfix-06-acceptance-path.txt) | positive path, replay, three concurrency rounds, and case h post-hardening |
| [`postfix-07-harness-run.txt`](./postfix-07-harness-run.txt) | one full unmodified `lifecycle-matrix.sh` run with its summary table |
| [`postfix-08-cleanup-final-state.txt`](./postfix-08-cleanup-final-state.txt) | close-out, the broker's final configuration, SPIRE and host state |
| [`postfix-09-secret-scan.txt`](./postfix-09-secret-scan.txt) | Appendix D scan over all 24 files, with a live positive control for both a nonce secret and the operator token |

### Close-out of this run

Full record: [`postfix-08-cleanup-final-state.txt`](./postfix-08-cleanup-final-state.txt).

- `user.spiffe-bootstrap` **unset on all nine instances** across both projects, checked one by one.
- Throwaway `spike-p8-operator` **deleted** — it held a copy of the operator Incus client key and of
  the mint token. `spike-guest-tmp` was deleted by the harness. No snapshots remain on any instance
  in either project.
- The short throwaway token was removed from `/state/auth`; only `mint-token` (mode 0600) remains.
  Staging directories were removed from both guests and from `spike-probe`.
- **Broker RUNNING**, binary `c534af07…a741`, listening on `[::]:8443`, `nonce_ttl 10m`,
  `max_nonce_ttl 10m`, `reap_interval 1m`, `reap_timeout 30s`, `reap_grace 2m`,
  `request_timeout 10s`, mint token at `/state/auth/mint-token`.
- **Guests A and B RUNNING** with `/dev/incus/sock` present. `spike-guest-a`
  `a955ca30-a0dc-4087-a369-37d53d389c5a`, generation now **`c32efc7b-f3d8-4637-9818-f8906c35543a`**.
  `spike-guest-b` `a4fec3ea-d4aa-4e6c-94c6-8295cee62338`, generation unchanged.
- `spike-authz-probe` untouched: `volatile.uuid` and `volatile.uuid.generation` both still
  `6d1c5ee3-5b2f-4ead-8e54-db985302fbdb`.
- SPIRE: `Found 1 attested agent`, `tpm_devid`, `Can re-attest: true`, agent 1.15.2; `Found 0
  entries`; `/live` and `/ready` both `200` from `spike-probe`.
- Host security state unchanged:
  `{"secure_boot_enabled":true,"encrypted_volumes":[{"state":"unlocked (TPM)","volume":"root"},
  {"state":"unlocked (TPM)","volume":"swap"}],"tpm_status":"ok","system_state_status":"system state
  is fully trusted","system_state_is_trusted":true}`. The recovery-key fields were never read.
- No TPM command, no reboot, no `incus admin os` mutation, no change to `spire-server`,
  `spire-agent` or their volumes, no code-worktree change, no repository gate, no Git command.

## Secret handling

**No nonce value exists in this directory.** Three mechanisms, all executed:

The scan below was run against the directory as it stood after the original run.
[`postfix-09-secret-scan.txt`](./postfix-09-secret-scan.txt) repeats every one of these checks over
the directory as it stands now, all 24 files, and adds a second live needle: the operator bearer
token the hardened mint endpoint requires. Both controls found their planted copies and neither
found anything in the evidence.

1. **The API cannot leak it to the operator.** The mint response has six fields and none of them
   can hold secret material; `operator-mint.sh` asserts this on every call and would exit `20`
   otherwise. The assertion fired zero times across roughly twenty mints.
2. **The scripts never print it.** `guest-bootstrap.sh` keeps the payload in one mode-0600 file
   that only `jq` reads, builds the request body with `jq` and pipes it to `curl` on stdin, and
   withholds any response body that could echo the value. The extra concurrency probe written for
   case d follows the same rule: `--data @file`, never `argv`. Every transcript shows
   `nonce=<redacted, present>`.
3. **An executed scan.** [`secret-scan.txt`](./secret-scan.txt) records the full run over every
   file in this directory. It checks Appendix D rule 4 directly — PEM `PRIVATE KEY` blocks, long
   base64 blobs, the strings `recovery` and `nonce=` — and adds two P8-specific checks: every
   64-hex token in the evidence is enumerated and matched to a known non-secret provenance
   (certificate fingerprints, the binary digest, the Incus server pin, the image selector, labelled
   payload digests), and a **live positive control** is run: a fresh nonce is minted for guest A,
   its secret is written to a 0600 file inside the guest without ever being printed, every evidence
   file is copied in beside it, and `grep -F -f secret` is run across them. The control must report
   zero matches while proving the grep itself works against a deliberately planted copy.

Payload SHA-256 digests, nonce IDs, certificate fingerprints, SPIFFE selectors and HTTP status
codes appear throughout; Appendix D rule 3 permits all of them.

## Commands exercised

```sh
# deployment
incus storage volume create ovh-incusos:local spike-broker-state --project default
incus launch images:debian/13 ovh-incusos:spike-broker --project default
incus config device add ovh-incusos:spike-broker state disk pool=local \
  source=spike-broker-state path=/state --project default
# server certificate issued inside spike-p3-stage, which mounts the spike CA at /ca
incus exec ovh-incusos:spike-p3-stage --project default -- sh -c \
  'openssl req -new -newkey rsa:2048 -nodes -keyout broker.key -out broker.csr -subj /CN=spike-broker
   openssl x509 -req -in broker.csr -CA /ca/root/spike-root-ca.pem -CAkey /ca/root/spike-root-ca.key \
     -out broker.crt -days 30 -sha256 -extfile san.cnf -extensions ext'
incus file pull  ovh-incusos:spike-p3-stage/tmp/brokercert/broker.crt - --project default \
  | incus file push - ovh-incusos:spike-broker/state/tls/broker.crt --project default --mode 0600
incus file push /tmp/incus-spiffe-broker-linux \
  ovh-incusos:spike-broker/usr/local/bin/incus-spiffe-broker --project default --mode 0755
incus exec ovh-incusos:spike-broker --project default -- \
  systemctl enable --now incus-spiffe-broker.service

# positive path
./operator-mint.sh a955ca30-a0dc-4087-a369-37d53d389c5a spike-spiffe     # BROKER_URL, BROKER_CACERT, BROKER_FINGERPRINT
incus exec ovh-incusos:spike-guest-a --project spike-spiffe -- \
  env BROKER_CACERT=/root/p8/broker-ca.pem /root/p8/guest-bootstrap.sh

# lifecycle matrix, unmodified, strict
INCUS_REMOTE=ovh-incusos PROJECT=spike-spiffe GUEST_A=spike-guest-a GUEST_B=spike-guest-b \
BROKER_URL=https://10.55.156.44:8443 BROKER_CACERT=/root/p8/broker-ca.pem \
BROKER_FINGERPRINT=7cedc92f… CASES="a b d e f g h i" STRICT_STATUS=1 ./lifecycle-matrix.sh
# case c, after restarting the broker with INCUS_SPIFFE_BROKER_NONCE_TTL=5s
CASES="c" STRICT_STATUS=1 SHORT_TTL_SECONDS=5 EXPIRY_WAIT_SECONDS=12 ./lifecycle-matrix.sh

# strict concurrency probe, inside guest A
/root/p8/concurrent-redeem.sh          # two workers spinning on one absolute instant

# payload movement never touches the operator disk
incus file pull ovh-incusos:<src>/root/p8/<f>.json - --project spike-spiffe \
  | incus file push - ovh-incusos:<dst>/root/p8/<f>.json --project spike-spiffe --mode 0600

# close-out
incus config unset ovh-incusos:<instance> user.spiffe-bootstrap --project <project>
incus delete ovh-incusos:spike-p8-operator --project default --force
incus delete ovh-incusos:spike-guest-tmp   --project spike-spiffe --force
incus delete ovh-incusos:spike-p8-gen      --project spike-spiffe --force
incus exec ovh-incusos:spire-server --project default -- /opt/spire/bin/spire-server agent list
incus query ovh-incusos:/os/1.0/system/security      # non-secret fields extracted with jq
```

## Cleanup and final state

Full transcript: [`cleanup-final-state.txt`](./cleanup-final-state.txt).

- `user.spiffe-bootstrap` is **unset on every instance in both projects** — nine instances checked
  one by one, including the ones that never carried it.
- Guest staging directories `/root/p8` removed from `spike-guest-a` and `spike-guest-b`; they held
  payload files. `jq` was installed in both guests during the run and was left in place.
- Throwaway instances deleted: `spike-guest-tmp` (case e), `spike-p8-gen` and its snapshot `p8-burn`
  (supplementary measurement), `spike-p8-operator` (the harness driver — it held a copy of the
  operator Incus client key). The case f snapshot `p8-generation-478` was deleted by the harness
  cleanup; both guests report `snapshots: []`.
- The broker private key scratch `/tmp/brokercert` was removed from `spike-p3-stage`.
- **Guests A and B are RUNNING and persist into P9.** `spike-guest-a` `volatile.uuid`
  `a955ca30-a0dc-4087-a369-37d53d389c5a`, generation now `d79b19ff-549c-4809-be8a-94822a41f506`
  (changed by case f, permanent, expected). `spike-guest-b` `a4fec3ea-d4aa-4e6c-94c6-8295cee62338`,
  generation unchanged.
- `spike-authz-probe` untouched: `volatile.uuid` and `volatile.uuid.generation` both still
  `6d1c5ee3-5b2f-4ead-8e54-db985302fbdb`.
- **`spike-broker` was deliberately left RUNNING** (`systemctl is-active` → `active`) because P9
  needs it. Its nonce TTL is back to `10m`; its state is in memory, so a restart invalidates
  outstanding nonces but nothing persistent is lost.
- The secret scan minted one control nonce for guest A (`4f4022e306b277a700c960be3f5097ac`).
  It was deliberately **not** redeemed, so it will simply expire; its instance key was cleared
  by hand afterwards, and `/root/scan` and `/root/p8` were removed from the guest. Both guests'
  sockets now report a visible-key list of `[]`. See [`secret-scan.txt`](./secret-scan.txt)
  Part 3 and the post-scan close-out at the end of
  [`cleanup-final-state.txt`](./cleanup-final-state.txt).
- SPIRE: `Found 1 attested agent`,
  `spiffe://spike.incus.internal/spire/agent/tpm_devid/fee6de975fb82fdbd3c7b7ea7e0b752412469fd0`,
  `tpm_devid`, agent 1.15.2, can re-attest; `Found 0 entries`; agent `/live` and `/ready` both
  `200` from the neighbouring `spike-probe`.
- Host security state, non-secret fields only:
  `{"secure_boot_enabled":true,"encrypted_volumes":[{"volume":"root","state":"unlocked (TPM)"},
  {"volume":"swap","state":"unlocked (TPM)"}],"tpm_status":"ok","system_state_status":"system state
  is fully trusted","system_state_is_trusted":true}`. The raw response also carries
  `drive_recovery_keys`, `pool_recovery_keys` and `config.encryption_recovery_keys`; those were
  never read into the transcript.
- No TPM command, no reboot, no `incus admin os` mutation, no change to `spire-server`,
  `spire-agent` or their volumes, no code-worktree change, no repository gate, no Git command.

## Teardown inventory additions

Append to Appendix E. Class in brackets is the ordered teardown class P11 executes.

| Artifact | Kind | Class | Note |
|---|---|---|---|
| `spike-broker` | container, project `default` | 2 | broker/attestor containers; left running for P9 |
| `spike-broker-state` | custom volume on pool `local`, project `default` | 2 | holds the broker TLS **private key**, both P5 Incus client keys, and `broker.env` |
| `/usr/local/bin/incus-spiffe-broker` | binary inside `spike-broker` | 2 | goes with the container |
| `incus-spiffe-broker.service` | systemd unit inside `spike-broker` | 2 | goes with the container |
| Broker server certificate `CN=spike-broker`, leaf `7cedc92f…ab93` | X.509 leaf issued by the spike root CA | 4 | expires 2026-09-16; no revocation mechanism exists in the spike |
| `jq` package installed in `spike-guest-a` and `spike-guest-b` | guest package | 1 | goes with the guests |
| `user.spiffe-bootstrap` on any instance | Incus config key | 5 | verified unset at close-out; re-check at teardown |
| `/state/auth/mint-token` inside `spike-broker` | operator bearer token, mode 0600 | 2 | **added 2026-08-17.** Goes with the `spike-broker-state` volume; it authorizes minting into any instance in `spike-spiffe` |

Already deleted during this run, listed so the inventory is not padded with ghosts:
`spike-p8-operator`, `spike-guest-tmp`, `spike-p8-gen` + snapshot `p8-burn`, snapshot
`p8-generation-478`, `/tmp/brokercert` in `spike-p3-stage`, `/root/p8` in both guests.

Deleted during the post-hardening run of 2026-08-17: a second `spike-p8-operator` (recreated to
drive the harness, deleted again because it held a copy of the operator Incus client key and the
mint token), a second `spike-guest-tmp` and snapshot `p8-generation-321` (both removed by the
harness's own verified cleanup, which also installed `jq`, `libjq1` and `libonig5` into that
instance before deleting it), `/state/auth/short-token` in `spike-broker`, `/root/p8fix` and
`/root/scan` in `spike-probe`, and `/root/p8` and `/root/scan` in both guests.

## Handoff

P9 inherits a working, running bootstrap channel:

- **Broker**: `spike-broker` at `https://10.55.156.44:8443`, leaf pin
  `7cedc92f3e349063cfd060bbe8be4da00dcab4b12b164d765ca926b05147ab93`, chain-validatable against the
  spike root CA (`b057b3f2…b1eb`, on volume `spike-ca-state`, mounted at `/ca` in
  `spike-p3-stage`). Endpoints `POST /v1alpha1/nonce` (operator) and `POST /v1alpha1/redeem`
  (guest). Nonce TTL `10m`. **Updated 2026-08-17:** the mint endpoint now requires
  `Authorization: Bearer <token>`; the token lives at `/state/auth/mint-token` inside `spike-broker`
  (mode 0600, digest `b611396f…a172`) and P9 must read it from there rather than expect an
  unauthenticated mint. `ttl_seconds` is an accepted optional mint field bounded by
  `-max-nonce-ttl` (`10m`). The redeem decoder is strict: send only `nonce_id`, `nonce`,
  `broker_url`, `broker_fingerprint` — an `instance_uuid` field is a `400`. An unredeemed nonce's
  key is withdrawn by the reaper roughly `expires_at + 2m`.
- **Guests**: `spike-guest-a` (`a955ca30-a0dc-4087-a369-37d53d389c5a`, generation
  **`c32efc7b-f3d8-4637-9818-f8906c35543a`** as of 2026-08-17 — the post-hardening harness run
  changed it again in case f, and this is the current value) and `spike-guest-b`
  (`a4fec3ea-d4aa-4e6c-94c6-8295cee62338`), both running with `incus-agent`, both with `jq`, `curl`
  and `openssl` present. Their `/root/p8` staging directories were removed; re-push
  `guest-bootstrap.sh` and the CA when P9 needs them.
- **No operator host on the bridge.** `spike-p8-operator` was deleted. P9 must recreate an operator
  container on `incusbr0` (or mint from inside a guest, as the supplementary measurement did) —
  the macOS workstation cannot reach `10.55.156.44`.
- **The redeem answer today is binding metadata plus the six frozen `incus:` selectors, and no key
  material.** P9 replaces that body with the exchange SVID. The selector set it must satisfy for
  guest A is `incus:uuid:a955ca30-…`, `incus:generation:d79b19ff-…`, `incus:project:spike-spiffe`,
  `incus:type:virtual-machine`, `incus:name:spike-guest-a`,
  `incus:image:9eb18b1a93682960e9e190cd818284ad4bcaf1740be9a435630a3b1dc60acee7`. Note that a
  registration entry keyed on `incus:generation:` for guest A must use the **current** value,
  `c32efc7b-f3d8-4637-9818-f8906c35543a`; the `d79b19ff…` above is the pre-2026-08-17 value and is
  stale.
- **Carry F3, F4 and F5 forward; F1 and F2 are closed in code.** F3 in particular is a P9 design
  input: treat every `409` as terminal and mint a fresh nonce. F2's practical advice still stands
  even though the reaper now exists — P9 should clear the key itself on any path that abandons a
  bootstrap rather than wait up to `reap-grace` plus a sweep for the broker to do it. And the
  bearer-token risk above is the question P9's go/no-go has to answer, because P9 is the phase where
  the nonce starts buying something durable. That question is now sharper, not softer:
  [`SECURITY_FINDINGS.md`](./SECURITY_FINDINGS.md) SEC-009 shows the leak does not even require a
  compromised guest, because the read-only credential can retrieve a live nonce from any instance in
  the project, and SEC-001 shows the process holding that credential is the same network listener
  that holds the config writer. Neither was fixed in this spike, by decision.

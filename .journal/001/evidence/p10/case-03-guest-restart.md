# P10 Case 3 — Guest agent process restart, then guest reboot

Live run on `ovh-incusos`, 2026-08-17 18:56–18:59 UTC. Full transcript:
[`case-03-guest-restart.txt`](./case-03-guest-restart.txt). No TPM command. No host reboot. No guest
deleted. `EXCHANGE_RETENTION` left at its default `shred` throughout; no `CHAIN_JQ`/`KEY_JQ`/
`BUNDLE_JQ` and no `PAYLOAD_FILE` in the recovery run.

## Case 3

**Verdict:** **PASS on all eight checkpoints.** The agent process restart failed closed on the
missing exchange keypair; the plain guest reboot left `volatile.uuid` **and**
`volatile.uuid.generation` unchanged; the nonce minted before the reboot therefore still redeemed
`200` afterwards; and the guest came back with the **same node SPIFFE ID** under an entirely new
credential set.

**Plan expectation, verbatim (`SPIKE_PLAN.md` P10 case 3):**
> Behavior matches the P9-defined re-attestation story.

Directly answered: P9's story is **fresh-credential-per-boot**, not agent-SVID persistence. Both arms
of this case confirm it — the process restart cannot recover without a fresh exchange credential
(*Observed 1*), and the reboot recovers only by redeeming a nonce through the full broker path
(*Observed 4*).

**Setup:**

| Item | Value |
|---|---|
| Guest A | `spike-guest-a`, `spike-spiffe`, virtual-machine, Running; `uptime -s` = `2026-08-17 18:27:24` |
| UUID / generation before | `a955ca30-a0dc-4087-a369-37d53d389c5a` / `37443652-6cce-4135-a88e-e8248e9d2a20` |
| Node before | `…/x509pop/incus/a955ca30-…`, serial `43821240236870179814166160036431104854`, expiry `2026-08-17 19:30:01 UTC` |
| Node selectors before | `x509pop:ca:fingerprint:ae3a15b9057fe658decd4e4f2f44862d48b9c393`, `x509pop:serialnumber:036c59df90d7dda40f0de6a11f480dc1` |
| Agent before | pid 953, `spire-agent run -config /run/spike-p9/agent.conf`, config sha256 `2c5332e78de18ae19351b263d2fef0c779b7e6dff37157c8c348ef53c943a57b`; **background process, no systemd unit** |
| On-disk agent state | `/var/lib/spire-agent/{agent-data.json (3358 B), bundle.pem (1539 B)}` — certificates only; `AGENT_KEY_MANAGER=memory` never wrote a node key |
| Exchange state | `/run/spike-exchange` present, **empty**, and **not a mountpoint** — the P9 `shred` end state; no `svid.pem`/`svid.key` |

Note on the CA selector: P9 recorded `x509pop:ca:fingerprint:ef7e6ffe…`. The live value is now
`ae3a15b9057fe658decd4e4f2f44862d48b9c393` — the server's CA has rolled since P9 (two CAs appear in
every fetched bundle, `CA #1` valid to `2026-08-17 22:04:03 UTC` and `CA #2` to `2026-08-18 10:04:11
UTC`). The invariant that matters held: the CA-fingerprint selector was **unchanged across this
case**, while the serial-number selector moved.

**Action:**

1. Recorded the anchors above.
2. **Process restart arm.** `kill $(cat /run/spike-p9/agent.pid)`, confirmed the process and socket
   were gone, then relaunched `spire-agent run -config /run/spike-p9/agent.conf` from the byte-
   identical on-disk config (sha256 re-verified) under `setsid`, capped at 25 s.
3. Minted **one** bootstrap value for A *before* the reboot —
   `nonce_id=4b6beea07cf603584d0e4fe27c2cc943`, `generation_uuid=37443652-…`, expiry
   `2026-08-17T19:06:52Z`. `user.spiffe-bootstrap` measured 268 bytes.
4. `incus restart ovh-incusos:spike-guest-a --project spike-spiffe`.
5. Waited for exec and for `/dev/incus/sock`; read the identity anchors and what survived inside.
6. Ran the canonical P9 harness **once**, no overrides, guest reading its own socket.
7. Created one temporary workload entry, waited ≥30 s for propagation, fetched from the in-guest
   Workload API, then deleted the entry.

**Expected:** the process restart fails closed with `unable to load keypair`; the plain reboot moves
neither `volatile.uuid` nor `volatile.uuid.generation`; the pre-reboot nonce therefore redeems; the
node SPIFFE ID is stable while the node SVID serial and the `x509pop:serialnumber:` selector are new.

**Observed:**

*1 — The process restart failed closed (C3-1): PASS.* Verbatim:

```
time="2026-08-17T18:56:33Z" level=info msg="Starting agent" data_dir=/var/lib/spire-agent version=1.15.2
time="2026-08-17T18:56:33Z" level=error msg="Failed to configure plugin" error="rpc error: code = InvalidArgument desc = unable to load keypair: open /run/spike-exchange/svid.pem: no such file or directory" external=false plugin_name=x509pop plugin_type=NodeAttestor subsystem_name=catalog
time="2026-08-17T18:56:33Z" level=error msg="Agent crashed" error="failed to configure plugin \"x509pop\": rpc error: code = InvalidArgument desc = unable to load keypair: open /run/spike-exchange/svid.pem: no such file or directory"
```

Afterwards: `<no spire-agent process>` and
`spire-agent healthcheck …` → `Agent is unhealthy: unable to determine health`. This is the correct
direction: the agent **did not** come back attested, which would have meant node key or exchange
material had survived the `shred` default.

*2 — The server-side node record persisted through the dead window (C3-8): PASS.* While nothing in
the guest could use it, `spire-server agent list` still showed
`…/x509pop/incus/a955ca30-…` serial `43821240236870179814166160036431104854`. The node record does
not self-delete; it is simply unusable without a credential.

*3 — The plain reboot moved neither anchor (C3-3): PASS.*

| Field | Before reboot | After reboot |
|---|---|---|
| `volatile.uuid` | `a955ca30-a0dc-4087-a369-37d53d389c5a` | unchanged |
| `volatile.uuid.generation` | `37443652-6cce-4135-a88e-e8248e9d2a20` | **unchanged** |
| `user.spiffe-bootstrap` | 268 bytes | **268 bytes — survived** |
| `uptime -s` | `2026-08-17 18:27:24` | `2026-08-17 18:56:58` |

This is the deliberate contrast with case 7: a snapshot restore reverted the config key *and* moved
the generation; a plain restart does neither. Exec was available ~10 s after the restart returned and
`GET /1.0` over `/dev/incus/sock` answered `200`.

*4 — Nothing usable survived inside the guest (C3-2): PASS.* `<no spire-agent process>`;
`/run/spike-p9` absent; `/run/spike-exchange` absent; `/var/lib/spire-agent` holding only
`agent-data.json` and `bundle.pem`. A strict PEM scan of the whole guest filesystem
(`grep -rIl` for the three `-----BEGIN … PRIVATE KEY-----` headers, binaries excluded) returned
exactly one file: `/run/incus_agent/agent.key` — **Incus's own guest-agent TLS key**, injected by
Incus into `tmpfs` at boot, unrelated to SPIRE. No SPIRE private key exists anywhere on the guest.
(A naive `grep -rl "PRIVATE KEY"` also matches the literal string compiled into `libcrypto`,
`spire-agent`, the ssh tools and the harness scripts; those are string constants, not keys, and
`-I` removes them.)

*5 — The pre-reboot nonce redeemed after the reboot (C3-4): PASS.* Canonical harness, guest reading
its own socket:

```
socket_read: GET /1.0/config/user.spiffe-bootstrap -> HTTP 200
redeem: HTTP 200
verdict: GRANTED
  resolved_generation=37443652-6cce-4135-a88e-e8248e9d2a20
  selectors=incus:uuid:a955ca30-…,incus:generation:37443652-…,incus:project:spike-spiffe,incus:type:virtual-machine,incus:name:spike-guest-a,incus:image:9eb18b1a9368…
```

Six `incus:` selectors, all re-derived host-side. Exchange leaf serial `8DDE1134A421C54013D778FBDDC09390`,
`not_before Aug 17 18:57:11 2026 GMT`, `not_after Aug 17 18:59:21 2026 GMT` — 130 s, as designed.

*6 — Node identity stable, credentials new (C3-5): PASS.*

| | Before | After |
|---|---|---|
| Node SPIFFE ID | `…/x509pop/incus/a955ca30-…` | **same** |
| Node SVID serial | `43821240236870179814166160036431104854` | `140753554988725634521572766511392636479` |
| Node expiry | `2026-08-17 19:30:01 UTC` | `2026-08-17 19:58:10 UTC` |
| `x509pop:serialnumber:` | `036c59df90d7dda40f0de6a11f480dc1` | `8dde1134a421c54013d778fbddc09390` |
| `x509pop:ca:fingerprint:` | `ae3a15b9057fe658decd4e4f2f44862d48b9c393` | **unchanged** |
| Agent pid | 953 | 801 |

The serial selector is exactly the new exchange leaf's serial, lowercased — the node identity is
re-derived from the stable UUID while the credential behind it is entirely fresh.

*7 — Harness result (C3-6): PASS.* Exit `0`, one nonce consumed:

```
RESULT phase=p9-bootstrap outcome=PASS nonce_id=4b6beea07cf603584d0e4fe27c2cc943 … key_manager=memory workload_api=/tmp/spire-agent/public/api.sock exchange_retention=shred exchange_material=shredded-and-unmounted
```

`/run/spike-exchange` was empty and **not a mountpoint** afterwards. The harness restates the story
this case exists to test: *"A restart or reboot therefore needs a FRESH nonce: one bootstrap per boot,
chosen rather than discovered."*

*8 — The in-guest Workload API serves again (C3-7): PASS.* Temporary entry
`6719c74b-e22b-48ec-b0d8-c5003206defd` (`…/guest/p10-c3-demo`, parent = A's node, `unix:uid:0`,
TTL 300); after a ≥30 s propagation wait the standard socket served it:

```
Received 1 svid after 1.757021ms
SPIFFE ID:              spiffe://spike.incus.internal/guest/p10-c3-demo
SVID Valid After:       2026-08-17 18:58:15 +0000 UTC
SVID Valid Until:       2026-08-17 19:03:25 +0000 UTC
```

serial `A7F539D9273491E22C4F0B484A747A31`, SAN `URI:spiffe://spike.incus.internal/guest/p10-c3-demo`.
Only the SPIFFE ID, serial and validity window were recorded; the fetched files were `shred -uz`'d in
the same command.

*9 — Out of scope, recorded rather than dropped.* P9 handoff item 8 — forcing a node re-attestation
on a *running* agent whose exchange material is already destroyed — was not attempted. The node SVID
has a one-hour life and renews near half-life, so observing it is a ~30-minute watch that does not
fit this wave. The C3-1 arm exercises the same missing-credential path at plugin-configure time and
is not a substitute for an in-flight re-attestation.

*10 — Host safety invariant after the case:*
`{"tpm_status":"ok","system_state_is_trusted":true,"secure_boot_enabled":true,"encrypted_volumes":[{"volume":"root","state":"unlocked (TPM)"},{"volume":"swap","state":"unlocked (TPM)"}]}` — unchanged.

**Cleanup:** temporary entry `6719c74b-e22b-48ec-b0d8-c5003206defd` deleted
(`Deleted 1 entries successfully`); `spire-server entry show` back to exactly the two chain entries.
Fetched SVID files shredded and verified absent. `user.spiffe-bootstrap` on A back to 1 byte (the
broker cleared it on redemption). Guest A left attested and serving, agent pid 801. No snapshot, no
clone, no entry left behind.

**Carried forward:** guest A's generation is still `37443652-6cce-4135-a88e-e8248e9d2a20`; a plain
`incus restart` of a guest preserves both the UUID and the generation *and* leaves an unredeemed
`user.spiffe-bootstrap` intact, so a value minted before such a restart is still good afterwards.

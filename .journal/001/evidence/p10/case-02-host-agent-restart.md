# P10 Case 2 — Host SPIRE Agent container restart

Live run on `ovh-incusos`, 2026-08-17 18:47–18:55 UTC. Full transcript:
[`case-02-host-agent-restart.txt`](./case-02-host-agent-restart.txt) (it also carries the wave-3
preflight, G-1 … G-11). No TPM command of any kind was executed. No host reboot. No guest deleted.
No registration entry created or deleted.

## Case 2

**Verdict:** **PASS on all six checkpoints.** The host agent loaded its **persisted** node SVID —
same SPIFFE ID, same serial, zero attestation work and zero TPM activity — and the broker
reconnected to the Broker API UDS **unaided**, with no broker restart. The only casualty of the
restart was the P9 Workload-API relay, which lives in the restarted container's PID namespace; it
was restored with the exact P9 argv.

**Plan expectation, verbatim (`SPIKE_PLAN.md` P10 case 2):**
> Node identity continuity; broker reconnects to Broker UDS.

Both halves are directly answered below: continuity in *Observed 2*, reconnection in *Observed 5*.

**Setup:**

| Item | Value |
|---|---|
| Host node | `spiffe://spike.incus.internal/spire/agent/tpm_devid/fee6de975fb82fdbd3c7b7ea7e0b752412469fd0`, serial `338245892702369297504124352385913862932`, expiry `2026-08-17 19:38:08 UTC`, `Can re-attest: true` |
| Guest A node | `spiffe://spike.incus.internal/spire/agent/x509pop/incus/a955ca30-a0dc-4087-a369-37d53d389c5a`, serial `43821240236870179814166160036431104854`, expiry `2026-08-17 19:30:01 UTC` |
| Guest A agent | pid 953, `spire-agent run -config /run/spike-p9/agent.conf`, `Agent is healthy.` — a background process, **no systemd unit in the guest** |
| Entries (by SPIFFE ID/parent/selector) | `…/incus-broker` ← tpm_devid node, `unix:uid:0`, TTL 3600 · `…/spire-exchange/incus/a955ca30-…` ← tpm_devid node, `incus:uuid:a955ca30-…`, TTL 120 |
| Broker | `incus-spiffe-broker.service` `active`, `enabled`, binary `4ed87f92ca113334c2e2e60127ae00131a47273ac476dd1d2f05b8f2e463fa45`, `LISTEN *:8443 users:(("incus-spiffe-br",pid=1238,fd=6))` |
| Sockets on the shared volume | `/hostagent/broker-run/broker.sock` inode 152 · `/hostagent/run/api.sock` inode 527 · `/hostagent/wlapi-relay.sock` inode 160, mtime `15:33:50` |
| Guest B | UUID `a4fec3ea-d4aa-4e6c-94c6-8295cee62338`, **no exchange entry** (G-3) — this absence is what makes the probe diagnostic |
| Host safety (five fields only) | `{"tpm_status":"ok","system_state_is_trusted":true,"secure_boot_enabled":true,"encrypted_volumes":[{"volume":"root","state":"unlocked (TPM)"},{"volume":"swap","state":"unlocked (TPM)"}]}` |
| Boot posture (G-10) | broker unit `enabled`; `boot.autostart` **unset on every instance in both projects**, and `volatile.last_state.power=RUNNING` on all eight — so Incus restores last power state rather than autostarting explicitly |

**G-11 — the relay's backgrounding form, recovered.** P9 records
`incus exec spire-agent -- /spike/bin/p9-wlapi-relay /spike/wlapi-relay.sock /spike/run/api.sock`,
which reads as a foreground command. Live observation resolves the apparent gap: the relay
**self-daemonizes inside the container**. The operator-side `incus exec` returns `0` immediately and
the relay keeps serving — verified 8 s later, and again through the probe below, with no exec
session held open (`incus operation list` shows no long-running WEBSOCKET operation). The P9 command
as recorded *is* the complete form; nothing operator-side needs to background it.

**Action:**

1. Asserted G-1 … G-11 (all green; transcript §preflight).
2. **Baseline probe before touching anything** — minted one guest-B nonce
   (`fa4b3f1bbcadfa687740a7997bee4c31`) and redeemed it from B, to record the healthy full-path
   signature the post-restart probe would have to reproduce.
3. `incus restart ovh-incusos:spire-agent` — the host agent container only, at `18:51:26Z`.
4. Read the host agent's own log for the restart. **No TPM command was run**: the TPM claim is read
   from SPIRE's log and the server's node list, nothing else.
5. Probed the relay socket, restored the relay, re-probed.
6. **Without restarting the broker**, minted one fresh B nonce (`4817655c230e15d303ff3b4bd73efec6`)
   and redeemed it from B.
7. Minted a third B nonce (`674225fbecda5f0265e44b7c3b261993`), staged its payload over **stdin**
   into a mode-0600 file *before* redemption, redeemed it, then replayed the staged value.
8. Re-checked node continuity, guest A, and the five host safety fields.

**Expected:** the node SPIFFE ID stays stable and the host returns to attested — either by loading
the persisted SVID or by a clean fresh `tpm_devid` re-attestation; the relay dies with the container;
the broker reaches `broker_no_svid` and returns a `503` burn for guest B; guest A is untouched.

**Observed:**

*1 — The agent loaded its persisted SVID. No re-attestation, no TPM work.* Verbatim from
`incus console ovh-incusos:spire-agent --show-log` after the restart:

```
INFO[0000] Starting agent                   data_dir=/spike/agent-data version=1.15.2
INFO[0000] Configured plugin                external=false plugin_name=tpm_devid plugin_type=NodeAttestor reconfigurable=false subsystem_name=catalog
INFO[0000] Configured plugin                external=false plugin_name=disk plugin_type=KeyManager reconfigurable=false subsystem_name=catalog
INFO[0000] Bundle loaded                    subsystem_name=attestor trust_domain_id="spiffe://spike.incus.internal"
INFO[0000] SVID loaded                      spiffe_id="spiffe://spike.incus.internal/spire/agent/tpm_devid/fee6de975fb82fdbd3c7b7ea7e0b752412469fd0" subsystem_name=attestor trust_domain_id="spiffe://spike.incus.internal"
```

A grep for `Node attestation|Starting node attestation|tpm|TPM` across the whole post-restart log
returns **0** matches beyond the plugin-load lines counted above — the `tpm_devid` node attestor was
configured and loaded but never invoked. **This is the persisted-SVID branch, not fresh
re-attestation.** It is possible because the agent's `disk` KeyManager holds the node key in
`/spike/agent-data` on the `spike-spire-agent-state` volume, which the container restart does not
touch, and because the node SVID (expiry `19:38:08 UTC`) had not expired during the ~3 s of downtime.

Both cached entries were re-hydrated immediately and their SVIDs minted:

```
DEBU[0000] Entry created   entry=718f0f2e-1430-4ea8-9179-ae7223724f6b selectors_added=1 spiffe_id="spiffe://spike.incus.internal/incus-broker" subsystem_name=cache_manager
DEBU[0000] Entry created   entry=6261b897-9852-4740-a80f-2dbd05979597 selectors_added=1 spiffe_id="spiffe://spike.incus.internal/spire-exchange/incus/a955ca30-a0dc-4087-a369-37d53d389c5a" subsystem_name=cache_manager
INFO[0000] Starting Workload and SDS APIs   address=/spike/run/api.sock network=unix subsystem_name=endpoints
INFO[0000] Starting SPIFFE Broker Endpoint  address=/spike/broker-run/broker.sock network=unix
```

*2 — Node identity continuity (C2-1, C2-2): PASS.* `spire-server agent list` after the restart is
byte-identical to before on both nodes — same SPIFFE ID **and** same serial
`338245892702369297504124352385913862932`, same expiry `2026-08-17 19:38:08 UTC`. A container
restart is invisible to the server-side node record.

*3 — Guest A was unaffected throughout (C2-3): PASS.* pid 953 unchanged,
`spire-agent healthcheck` → `Agent is healthy.`, node serial `43821240236870179814166160036431104854`
unchanged. Guest A's agent talks to `spire-server` at `10.55.156.67:8081`, not to the host agent, so
the host-agent restart has no path to it.

*4 — The relay died with the container, and its socket file survived stale (C2-4): PASS.*
Before restoration, from the broker container:

```
$ curl -sS --max-time 5 --unix-socket /hostagent/wlapi-relay.sock http://localhost/
curl: (7) Failed to connect to localhost port 80 after 0 ms: Could not connect to server
$ stat -c '%n inode=%i mtime=%y' /hostagent/wlapi-relay.sock
/hostagent/wlapi-relay.sock inode=160 mtime=2026-08-17 15:33:50.897722799 +0000
```

The socket **file** persisted on the shared volume with its original inode — it is a stale entry, not
a live endpoint. Re-running the exact P9 command replaced it; the relay unlinks before binding, so
the "stale socket blocks bind" contingency in the runbook never fired and **no file was removed by
hand**:

```
/hostagent/wlapi-relay.sock inode=422 mtime=2026-08-17 18:52:39.286146608 +0000
curl: (1) Received HTTP/0.9 when not allowed
```

`curl (1)` is a *successful* connect to a peer speaking gRPC, in direct contrast with the `curl (7)`
refusal above. Inode `160` → `422` is the re-bind.

*5 — The broker reconnected to the Broker UDS unaided (C2-5): PASS.* With the broker service
untouched (`LISTEN *:8443 users:(("incus-spiffe-br",pid=1238,fd=6))` — **same pid 1238 as before the
restart**), the guest-B probe produced exactly the documented healthy-path burn:

```
redeem: HTTP 503
RESULT phase=p9-bootstrap outcome=ERROR reason=redeem_rejected status=503 nonce_id=4817655c230e15d303ff3b4bd73efec6 broker_reason=nonce_consumed_without_svid
```

and the broker's own log line, verbatim:

```
{"time":"2026-08-17T18:53:23.503263013Z","level":"ERROR","msg":"nonce consumed but no exchange SVID was issued","operation":"redeem","outcome":"burned","nonce_id":"4817655c230e15d303ff3b4bd73efec6","instance_uuid":"a4fec3ea-d4aa-4e6c-94c6-8295cee62338","project":"spike-spiffe","failure_class":"broker_no_svid","peer_address":"10.55.156.75:33788","http_status":503,"code":"nonce_consumed_without_svid","reason":"broker delivered no X.509-SVID: response carried an empty SVID list"}
```

`failure_class=broker_no_svid` is the load-bearing field. It proves the request travelled the whole
path: the broker obtained **its own** SVID over the restored relay, dialled
`/hostagent/broker-run/broker.sock`, completed mutual SPIFFE TLS against the `tpm_devid` node, and
the host agent's `incus-attestor` re-derived selectors — only then did the server match nothing. The
host agent's log confirms the far end of that path independently:

```
DEBU[0113] attesting incus instance reference   external=true instance_uuid=a4fec3ea-d4aa-4e6c-94c6-8295cee62338 plugin_name=incus plugin_type=WorkloadAttestor project=spike-spiffe subsystem_name=incus.incus-attestor timestamp="2026-08-17T18:53:23.496Z"
DEBU[0113] attested incus instance reference    external=true plugin_name=incus plugin_type=WorkloadAttestor selector_count=6 subsystem_name=incus.incus-attestor timestamp="2026-08-17T18:53:23.502Z"
DEBU[0113] Subscribing to cache changes         broker_peer="spiffe://spike.incus.internal/incus-broker" method=SubscribeToX509SVID …
```

`DEBU[0113]` is 113 s of *post-restart* agent uptime: this is the new process, not a pre-restart
record. The signature matches the pre-restart baseline probe (`DEBU[59254]`, nonce
`fa4b3f1bbcadfa687740a7997bee4c31`, also `selector_count=6`, also `503`/`broker_no_svid`) line for
line. **The broker was never restarted, so the fallback branch in the runbook — "restart broker once
and retry, record reconnect behaviour as a finding" — did not fire. There is no reconnect defect to
report.**

*6 — The burned nonce is genuinely spent (C2-6): PASS.* Third B nonce, payload staged over stdin
before redemption:

```
redeem: HTTP 503   … broker_reason=nonce_consumed_without_svid     (burn)
redeem: HTTP 409   … broker_reason=conflict                        (replay of the same value)
```

Two different codes for two different facts, as P9 A15 established. `user.spiffe-bootstrap` on guest
B measured 1 byte (unset) after every burn.

*7 — Health-endpoint behaviour, recorded accurately.* The broker serves **no** health endpoints; both
probes against its own TLS listener return `404`:

```
GET /live  -> 404
GET /ready -> 404
```

`/live` and `/ready` belong to the **host SPIRE agent** (`INFO[0000] Serving health checks
address="0.0.0.0:8080"`), and both returned `200` after the restart. Broker liveness is therefore the
`LISTEN *:8443` line plus live traffic, never a health probe.

*8 — Incidental observation.* The restart moved the `spire-agent` container's address from
`10.55.156.121` to `10.55.156.104`. Nothing in the chain depends on it: the broker reaches the agent
over shared-volume UNIX sockets, and the probe succeeded across the change.

*9 — Host safety invariant re-read after the case:*
`{"tpm_status":"ok","system_state_is_trusted":true,"secure_boot_enabled":true,"encrypted_volumes":[{"volume":"root","state":"unlocked (TPM)"},{"volume":"swap","state":"unlocked (TPM)"}]}` — unchanged.

**Cleanup:** three guest-B nonces minted and all three spent; B's `user.spiffe-bootstrap` verified
clear (1 byte) after each; the one staged payload copy `shred -uz`'d in guest B and verified absent
(`ls: cannot access '/run/p10c2-b.json': No such file or directory`). No registration entry was
created or deleted. No snapshot, clone or instance change. The relay was left running. Guest A was
never touched.

**Carried forward:** the relay self-daemonizes, so restoring it after a container restart or a host
reboot is one `incus exec` with the P9 argv and needs no operator-side backgrounding and no stale-
socket cleanup.

# P10 Case 1 — Full host reboot (run last)

Original continuity-control run on `ovh-incusos`, 2026-08-17 19:00–19:05 UTC. Full transcript:
[`case-01-host-reboot.txt`](./case-01-host-reboot.txt); wave end state in
[`wave-03-final-state.txt`](./wave-03-final-state.txt). Exactly one host reboot was executed in this
original run, at the end of the wave. No operator-invoked TPM command ran; no persistent TPM object
was intentionally created, evicted, or written.

## Case 1

**Final verdict:** **PASS WITH FINDINGS.** The original reboot is the persisted-SVID continuity
control. The additive corrective reboot directly proves fresh post-boot `tpm_devid` attestation
under the same host node SPIFFE ID with a new serial. Both runs preserved the TPM-unlock invariant,
returned all eight instances unaided, and restored the guest chain.
**C1-F1 (Medium):** the broker's systemd service started on boot but could not finish starting
because the P9 Workload-API relay did not survive the host reboot. Restoring the relay unblocked the
broker without a restart.
**C1-F2 (Medium):** configured bootstrap trust can become stale after CA rotation. Deleting
persisted agent state then fails closed and drops dependent identity services until bootstrap trust
is refreshed. No bypass or impersonation occurred.

**Plan expectation, verbatim (`SPIKE_PLAN.md` P10 case 1):**
> Host agent re-attests via `tpm_devid`; guests recover per P9 §4 story; TPM-unlock invariant re-verified.

Across the two runs, all three expectations are directly answered: the original reboot's
persisted-SVID continuity control in *Observed 3*; the additive reboot's fresh `tpm_devid`
attestation in *The gap-closing evidence*; the guest story in *Observed 7*; and the invariant in
*Observed 1*, *Observed 9*, and the corrective closing state.

**Setup — frozen pre-reboot record (19:00:5xZ):**

| Item | Value |
|---|---|
| Host node | `…/spire/agent/tpm_devid/fee6de975fb82fdbd3c7b7ea7e0b752412469fd0`, serial `338245892702369297504124352385913862932`, expiry `2026-08-17 19:38:08 UTC`, `Can re-attest: true` |
| Guest A node | `…/spire/agent/x509pop/incus/a955ca30-a0dc-4087-a369-37d53d389c5a`, serial `140753554988725634521572766511392636479`, expiry `2026-08-17 19:58:10 UTC` |
| Entry 1 | `…/incus-broker` ← parent `…/tpm_devid/fee6de97…`, selector `unix:uid:0`, TTL 3600 (`718f0f2e-1430-4ea8-9179-ae7223724f6b`) |
| Entry 2 | `…/spire-exchange/incus/a955ca30-…` ← parent `…/tpm_devid/fee6de97…`, selector `incus:uuid:a955ca30-…`, TTL 120 (`6261b897-9852-4740-a80f-2dbd05979597`) |
| Guest A | UUID `a955ca30-a0dc-4087-a369-37d53d389c5a`, generation `37443652-6cce-4135-a88e-e8248e9d2a20`, agent pid 801, `Agent is healthy.`, `uptime -s` `2026-08-17 18:56:58` |
| Broker | `active` + `enabled`, digest `4ed87f92ca113334c2e2e60127ae00131a47273ac476dd1d2f05b8f2e463fa45`, `LISTEN *:8443 users:(("incus-spiffe-br",pid=1238,fd=6))`, `hostagent` disk device → pool `local`, source `spike-spire-agent-state` |
| Sockets | `broker.sock` inode 1798 · `api.sock` inode 533 · `wlapi-relay.sock` inode 422 (the relay restored in case 2) |
| Host safety | `{"tpm_status":"ok","system_state_is_trusted":true,"secure_boot_enabled":true,"encrypted_volumes":[{"volume":"root","state":"unlocked (TPM)"},{"volume":"swap","state":"unlocked (TPM)"}]}` |
| Host uptime | `54597.07` s (`/proc/uptime` seen from a container, which shares the host kernel) |
| Boot posture | broker unit `enabled`; `boot.autostart` **unset** on all eight instances, `volatile.last_state.power=RUNNING` on all eight |

**Action:**

1. Froze the record above.
2. `incus admin os system reboot ovh-incusos: --force` at `19:00:56Z` — **exactly once**.
3. Polled for the host API; read the five safety fields **first**, before any SPIRE work.
4. Instance sweep, host agent log, broker state, relay state.
5. Restored the relay with the case-2 command; observed the broker.
6. Guest A: state check, one fresh nonce, one canonical harness run, one temporary entry, delete.
7. Re-read the five safety fields to close.

**Expected:** the invariant holds; instances return; the host node stays attested under the same
SPIFFE ID; the broker survives with its digest, listener and socket exposure; the relay is dead and
restorable; guest A has no surviving agent or private key and recovers with one nonce; both entries
survive.

**Observed:**

*1 — The safety invariant held, and it was the first thing read (C1-1): PASS.* At `19:02:21Z`,
76 s after the reboot command:

```
{"tpm_status":"ok","system_state_is_trusted":true,"secure_boot_enabled":true,"encrypted_volumes":[{"volume":"root","state":"unlocked (TPM)"},{"volume":"swap","state":"unlocked (TPM)"}]}
```

Root and swap unlocked by the TPM. The `drive_recovery_keys`, `pool_recovery_keys` and
`config.encryption_recovery_keys` fields of that same response were never selected, printed or
stored.

*2 — No operator TPM mutation (C1-2): PASS.* No operator-invoked TPM command ran, and no persistent
TPM object was intentionally created, evicted, or written. Persistent TPM namespace equality was
not directly re-inventoried in either P10 reboot run; the prior P3 namespace evidence remains
separate.

*3 — The host agent loaded its persisted SVID; it did not re-attest (C1-3): PASS, branch recorded.*
The reboot is real — host uptime went `54597.07` → `24.30` s. Verbatim from the agent's own log:

```
INFO[0000] Starting agent            data_dir=/spike/agent-data version=1.15.2
INFO[0000] Configured plugin         external=false plugin_name=tpm_devid plugin_type=NodeAttestor reconfigurable=false subsystem_name=catalog
INFO[0000] Bundle loaded             subsystem_name=attestor trust_domain_id="spiffe://spike.incus.internal"
INFO[0000] SVID loaded               spiffe_id="spiffe://spike.incus.internal/spire/agent/tpm_devid/fee6de975fb82fdbd3c7b7ea7e0b752412469fd0" subsystem_name=attestor trust_domain_id="spiffe://spike.incus.internal"
INFO[0005] Starting SPIFFE Broker Endpoint   address=/spike/broker-run/broker.sock network=unix
INFO[0005] Starting Workload and SDS APIs    address=/spike/run/api.sock network=unix subsystem_name=endpoints
INFO[0005] Serving health checks             address="0.0.0.0:8080" subsystem_name=health
```

A case-insensitive grep of the whole post-reboot log for
`Node attestation was successful|Starting node attestation|tpmrm0|cannot open TPM` returns **0**.
`spire-server agent list` shows the tpm_devid node still attested with the **identical serial**
`338245892702369297504124352385913862932` and the identical expiry `19:38:08 UTC`.

**This is worth stating precisely, because the plan's wording and the observation differ.** The plan
says the host agent "re-attests via `tpm_devid`". What actually happens on this host — as in P3, and
as in case 2 above — is that the agent finds a still-valid node SVID and its key in
`/spike/agent-data` on the `spike-spire-agent-state` volume and loads it; `tpm_devid` is configured
and available but is not exercised. The `tpm_devid` path is therefore **not** re-proven by a host
reboot as long as the persisted SVID outlives the downtime (here: ~75 s of downtime against a node
SVID with ~35 min of life left). A reboot that outlasts the node SVID would take the attestation
branch instead; that branch is the one P3 proved, and this wave did not force it.

*4 — Every instance returned unaided (C1-4): PASS.* All eight were `RUNNING` on the first poll after
the API answered, at `19:02:28Z`, without any manual start. Against G-10 this is the
`volatile.last_state.power=RUNNING` restore path rather than explicit `boot.autostart` — Incus
restores the previous power state, and `boot.autostart` is unset everywhere.

*5 — The broker survived, but could not finish starting until the relay came back — finding C1-F1
(C1-5, C1-6): PASS with a finding.* Immediately after the reboot:

- `systemctl is-active` → `active`; `is-enabled` → `enabled`; Main PID 173, started `19:02:11 UTC`;
- digest unchanged: `4ed87f92ca113334c2e2e60127ae00131a47273ac476dd1d2f05b8f2e463fa45`;
- `hostagent` disk device present, `/hostagent/broker-run/broker.sock` present (inode 384, recreated
  by the restarted host agent), `/hostagent/run/api.sock` present (inode 513);
- **but** `ss -ltnp | grep 8443` was empty and a TLS request to `https://10.55.156.44:8443/…` was
  refused, and the journal after `Started incus-spiffe-broker.service` at `19:02:11` contained
  **nothing** — no `incus-spiffe-broker listening` line.

The cause is the relay. `curl --unix-socket /hostagent/wlapi-relay.sock` returned
`curl: (7) … Could not connect` — the relay died with the host agent container's PID namespace, as in
case 2. The broker cannot serve without its **own** SVID, and its only SVID source is that relay, so
it sat in startup. Restoring the relay with the case-2 command:

```
$ incus exec ovh-incusos:spire-agent -- /spike/bin/p9-wlapi-relay /spike/wlapi-relay.sock /spike/run/api.sock
relay_exec_rc=0
/hostagent/wlapi-relay.sock inode=134 mtime=2026-08-17 19:03:20.288150558 +0000
curl: (1) Received HTTP/0.9 when not allowed        ← connect succeeds, peer speaks gRPC
```

and 9 s later, with **no broker restart** and the same Main PID 173:

```
Aug 17 19:03:29 spike-broker incus-spiffe-broker[173]: {"time":"2026-08-17T19:03:29.91496386Z","level":"INFO","msg":"incus-spiffe-broker listening","listen_address":"[::]:8443","redeem_url":"https://10.55.156.44:8443/v1alpha1/redeem","tls_fingerprint":"7cedc92f3e349063cfd060bbe8be4da00dcab4b12b164d765ca926b05147ab93",…,"broker_socket":"/hostagent/broker-run/broker.sock","workload_api_socket":"/hostagent/wlapi-relay.sock",…}
LISTEN 0 4096 *:8443 *:* users:(("incus-spiffe-br",pid=173,fd=6))
```

Same TLS fingerprint `7cedc92f…ab93`, so no identity or certificate changed. **C1-F1 is a property of
the spike relay scaffolding, not of the architecture**: the broker's dependency on a
single-identity byte relay for its own SVID (P9 finding F1) becomes a boot-ordering dependency after
a host reboot. The broker's behaviour is correct — it fails closed by not serving rather than serving
without an identity. A production topology that gives the broker its own attested SVID source removes
this entirely.

*Health endpoints, recorded accurately.* The broker serves **no** `/live` or `/ready`. In case 2,
with the broker listening, both returned `404`. In the window measured here — before the relay was
restored — the same probes returned `000` with `curl: (7) … Could not connect`, because the listener
did not exist yet. Broker liveness is the `LISTEN *:8443` line plus live traffic; `/live` and
`/ready` belong to the **host SPIRE agent** (`Serving health checks address="0.0.0.0:8080"`).

*6 — Guest A came back with nothing usable (C1-7): PASS.* `uptime -s` = `2026-08-17 19:02:12`;
`<no spire-agent process>`; `/run/spike-p9` and `/run/spike-exchange` both absent;
`/var/lib/spire-agent` holding only `agent-data.json` and `bundle.pem`. The strict PEM scan
(`grep -rIl` for the three `-----BEGIN … PRIVATE KEY-----` headers) returned exactly one file,
`/run/incus_agent/agent.key` — Incus's own guest-agent TLS key on tmpfs, not SPIRE material. Both
guests' `user.spiffe-bootstrap` measured 1 byte (clear).

*7 — Generation across a host reboot (C1-8): measured, unchanged.* `volatile.uuid`
`a955ca30-a0dc-4087-a369-37d53d389c5a` and `volatile.uuid.generation`
`37443652-6cce-4135-a88e-e8248e9d2a20` were both identical before and after. A host reboot therefore
behaves like the plain guest restart of case 3, not like the snapshot restore of case 7. This was
measurement, not confirmation — no prior evidence covered a host reboot.

*8 — Recovery with one nonce and one harness run (C1-9): PASS.*
`nonce_id=87ae86f3c51a8760c1646e43def904bb` (generation `37443652-…`), read by the guest from its own
`/dev/incus/sock` (`HTTP 200`), canonical harness, no overrides, default `shred`:

```
redeem: HTTP 200
verdict: GRANTED   resolved_generation=37443652-6cce-4135-a88e-e8248e9d2a20
  selectors=incus:uuid:a955ca30-…,incus:generation:37443652-…,incus:project:spike-spiffe,incus:type:virtual-machine,incus:name:spike-guest-a,incus:image:9eb18b1a9368…
exchange: serial=C7AC8E6CDC8C9FEBBF47823FDC2127BA not_before=Aug 17 19:04:05 2026 GMT not_after=Aug 17 19:06:15 2026 GMT
agent: node attestation succeeded, node_spiffe_id=spiffe://spike.incus.internal/spire/agent/x509pop/incus/a955ca30-a0dc-4087-a369-37d53d389c5a
RESULT phase=p9-bootstrap outcome=PASS … exchange_retention=shred exchange_material=shredded-and-unmounted
```

exit `0`. Node identity is unchanged and credentials are new:

| | Before the reboot | After recovery |
|---|---|---|
| Node SPIFFE ID | `…/x509pop/incus/a955ca30-…` | **same** |
| Node SVID serial | `140753554988725634521572766511392636479` | `255755278229189093346956051979456409234` |
| `x509pop:serialnumber:` | `8dde1134a421c54013d778fbddc09390` | `c7ac8e6cdc8c9febbf47823fdc2127ba` |
| `x509pop:ca:fingerprint:` | `ae3a15b9057fe658decd4e4f2f44862d48b9c393` | unchanged |

*9 — Both chain entries survived, asserted by SPIFFE ID / parent / selector (C1-10): PASS.* The
server datastore lives on `spike-spire-server-state`, and after the reboot `entry show` returns
exactly the two entries with unchanged SPIFFE IDs, parents (`…/tpm_devid/fee6de97…` for both),
selectors (`unix:uid:0`, `incus:uuid:a955ca30-…`) and TTLs (3600, 120). Their entry IDs also happen
to be unchanged (`718f0f2e-…`, `6261b897-…`), but the assertion does not rest on that.

*10 — The in-guest Workload API serves again (C1-11): PASS.* Temporary entry
`de4ab869-3440-4147-88c3-47409acc11b0` (`…/guest/p10-c1-demo`, parent = A's node, `unix:uid:0`,
TTL 300); after a ≥30 s propagation wait:

```
Received 1 svid after 1.629981ms
SPIFFE ID:              spiffe://spike.incus.internal/guest/p10-c1-demo
SVID Valid After:       2026-08-17 19:04:30 +0000 UTC
SVID Valid Until:       2026-08-17 19:09:40 +0000 UTC
```

serial `2CCE6AABF7B6898DF428E0239E58CAF9`, SAN `URI:spiffe://spike.incus.internal/guest/p10-c1-demo`.

*11 — Closing safety read:* identical to *Observed 1* — `tpm_status: ok`,
`system_state_is_trusted: true`, `secure_boot_enabled: true`, root and swap `unlocked (TPM)`.

**Cleanup:** temporary entry `de4ab869-3440-4147-88c3-47409acc11b0` deleted (`Deleted 1 entries
successfully`); `entry show` back to exactly the two chain entries. Fetched SVID files `shred -uz`'d
and verified absent. One nonce minted and consumed. The relay was left running; the broker active and
listening; both guests `RUNNING`; guest A attested and serving. No snapshot, clone, or instance
deletion occurred in this wave. No persistent TPM object was intentionally created, evicted, or
written.

**Carried forward:**
1. A host reboot preserves guest A's `volatile.uuid.generation` (`37443652-6cce-4135-a88e-e8248e9d2a20`).
2. Recovery order after a host reboot is **relay first, then anything that needs the broker** — the
   broker will otherwise sit in startup indefinitely without binding (C1-F1).
3. Every nonce minted during this wave is dead.
4. The host agent's reboot recovery observed here is *persisted-SVID load*, not `tpm_devid`
   re-attestation; a downtime longer than the node SVID's remaining life would be needed to exercise
   the attestation branch on a reboot.

---

## Corrective rerun — forcing the `tpm_devid` branch (additive, 2026-08-17 19:24–19:35 UTC)

The preceding section records the **original** case-1 run as the persisted-SVID continuity control.
This section is **additive**: a second, deliberately conditioned host reboot run that closed the
literal fresh-attestation gap. Transcript:
[`case-01-host-reboot-reattest.txt`](./case-01-host-reboot-reattest.txt); refreshed end state in the
addendum of [`wave-03-final-state.txt`](./wave-03-final-state.txt). Exactly one additional host
reboot was executed. No operator-invoked TPM command ran; no persistent TPM object was intentionally
created, evicted, or written. Fresh `tpm_devid` attestation necessarily accessed the TPM
transiently. The DevID triplet checksums were byte-identical before and after.

### Why a rerun at all

*Observed 3* above records, precisely, that the first reboot's host-agent recovery was a
**persisted-SVID load**, not `tpm_devid` re-attestation: the node SVID had ~35 min of life left
against ~75 s of downtime, so the agent never invoked the attestor. Against the plan's literal
wording — "Host agent re-attests via `tpm_devid`" — that is a **PARTIAL**, and the original text said
so rather than smoothing it over. The reboot-continuity property it *did* prove is real and is
retained. This rerun supplies the missing half.

### The control that makes the branch reachable

P3 established that the SPIRE 1.15.2 agent data directory holds `agent-data.json` (SVID and bundle
state) and `keys.json` (disk KeyManager state). The operator stopped the agent and removed only
`agent-data.json`; `keys.json` was unchanged immediately after that removal. The operator then
rebooted the host and let the agent start without a cached SVID.

Two supporting moves, both temporary and both reverted:

- `boot.autostart` on `spire-agent` was **unset** (the original run showed Incus restores instances
  via `volatile.last_state.power`, so a container left `STOPPED` across a reboot stays stopped). It
  was set to `true` for the rerun and **unset again** afterwards.
- Before removal, `agent-data.json` was copied to a mode-`0600` backup on the same encrypted volume.
  The backup remained through successful attestation and was then deleted.

### What happened — including a failure that had to be fixed

**The first post-reboot agent start crashed.** It is reported here because it is the most useful
thing this rerun found. All eight instances returned unaided (`spire-agent` among them, via the
temporary autostart) and the safety invariant was green 75 s after the reboot command; then:

```
DEBU[0000] No pre-existing agent SVID found. Will perform node attestation
WARN[0000] Keys recovered, but no SVID found. Generating new keypair
INFO[0000] SVID is not found. Starting node attestation
INFO[0030] Trust Bundle and Server don't agree, bootstrapping again
WARN[0030] Failed to retrieve attestation result  error="could not open attestation stream to SPIRE
             server: … transport: authentication handshake failed: x509svid: could not verify leaf
             certificate: x509: certificate signed by unknown authority"
…
ERRO[0065] Agent crashed
```

The fresh-attestation branch was entered as intended. The operator removed only
`agent-data.json`; `keys.json` was unchanged at that moment. SPIRE's disk KeyManager then
intentionally rewrote `keys.json` when it generated a new keypair. The crash was not a `tpm_devid`
rejection: the agent could not open the attestation stream because bootstrap trust was stale.

The cause, confirmed by comparing the two bundles directly:

| Bundle | Authorities present |
|---|---|
| SPIRE server, live (`bundle show`) | `129944772266556437062337838904092526589` **and** `336849817190210772708609465223417189934` |
| `/spike/conf/agent-trust-bundle.pem` on disk (`609c0bc7…ee94`) | `129944772266556437062337838904092526589` only |

The SPIRE server's CA **rotated mid-spike** — precisely the event P3 flagged ("the agent SVID TTL is
1 hour with a 24-hour CA TTL, so an authority rotation is still expected mid-spike"). The persisted
`agent-data.json` carried the *current* bundle; removing it dropped the agent back to its bootstrap
`trust_bundle_path`, which still held only the *old* authority. The later in-guest SVID fetch shows
`CA #1` and `CA #2` side by side, corroborating the rotation independently.

**C1-F2 (Medium): configured bootstrap trust can become stale after CA rotation.** Deleting
persisted agent state then fails closed and drops dependent identity services until bootstrap trust
is refreshed. Here, the agent crashed before opening the attestation stream, and the broker stayed
down because it depended on the host agent for its own SVID. No bypass or impersonation occurred.

Recovery refreshed `/spike/conf/agent-trust-bundle.pem` from the authoritative
`spire-server bundle show` over the authenticated Incus administrative channel
(`609c0bc7…ee94` → `d5514eec…d520`). This preserved the existing administrative trust boundary; no
unverified network source supplied the bundle. No DevID file or other configuration changed.

Production mitigation is rotation-aware, atomic distribution of overlapping current and next
authorities, plus a mandatory pre-delete validation gate that confirms the configured bootstrap
bundle chains to the server before persisted agent state is removed.

### The gap-closing evidence

Second start, verbatim from the agent's own log, with `agent-data.json` still carrying no SVID:

```
INFO[0000] Starting agent            data_dir=/spike/agent-data version=1.15.2
INFO[0000] Bundle loaded             subsystem_name=attestor trust_domain_id="spiffe://spike.incus.internal"
DEBU[0000] No pre-existing agent SVID found. Will perform node attestation  subsystem_name=attestor
WARN[0000] Keys recovered, but no SVID found. Generating new keypair        subsystem_name=attestor
INFO[0000] SVID is not found. Starting node attestation                     subsystem_name=attestor
INFO[0033] Node attestation was successful   reattestable=true
              spiffe_id="spiffe://spike.incus.internal/spire/agent/tpm_devid/fee6de975fb82fdbd3c7b7ea7e0b752412469fd0"
INFO[0033] Starting SPIFFE Broker Endpoint   address=/spike/broker-run/broker.sock network=unix
INFO[0033] Starting Workload and SDS APIs    address=/spike/run/api.sock network=unix
INFO[0034] Health check recovered            check=agent failures=26
```

Every element the plan's wording asks for is present and direct:

| Required | Observed |
|---|---|
| `No pre-existing agent SVID` | `DEBU[0000] No pre-existing agent SVID found. Will perform node attestation` |
| `Starting node attestation` | `INFO[0000] SVID is not found. Starting node attestation` |
| `Node attestation was successful` | `INFO[0033] Node attestation was successful` |
| `reattestable=true` | on that same line |
| Same host node SPIFFE ID | `…/spire/agent/tpm_devid/fee6de975fb82fdbd3c7b7ea7e0b752412469fd0` — unchanged, because it derives from the DevID certificate |
| New serial | `320634660006268655429054830322439136727` → **`132093680856743140626168429589948833700`** (expiry `20:07:07` → `20:31:04 UTC`) |
| Elapsed | **33 s** agent start → attestation success, against P3's three measurements of 33.32 / 33.46 / 33.48 s — the physical-TPM cost, reproduced a fourth time |
| Five host safety fields green | `tpm_status: ok`; `system_state_is_trusted: true`; `secure_boot_enabled: true`; root and swap `unlocked (TPM)` |
| Chain restored | Host and guest nodes attested; exactly two chain entries retained; broker listening; guest A healthy and serving the Workload API |

Fresh `tpm_devid` attestation necessarily performed transient TPM access. No operator-invoked TPM
command ran, and no persistent TPM object was intentionally created, evicted, or written.
Persistent TPM namespace equality was not directly re-inventoried in this corrective rerun; the
prior P3 evidence remains separate.

The 26-failure health-check window before recovery is the same signature P3 recorded for a cold
attestation. `Success after 2m56.406944934s attempts=3` on the adjacent line is the
`TrustBundleSources` logger counting from the *first*, crashed start; the attestation itself took
33 s of the second start.

### Chain restoration

Recovery order was the one case 1 itself established (C1-F1): **relay first**. The broker's unit
started at `19:28:06` and sat without binding for five minutes — longer than the original run's 78 s,
because it was additionally waiting on the host agent's own recovery. It bound at `19:33:06`, 49 s
after the relay returned, with **no restart** (same Main PID 172) and the **same** TLS fingerprint
`7cedc92f…ab93`.

Guest A came back with `volatile.uuid.generation` unchanged (`37443652-…`, matching *Observed 7*),
no agent process and no exchange tmpfs. It recovered with **one** fresh nonce
(`e9cd875809bc2f462807786a8fdd1ac2`) and **one** canonical harness run, no overrides, default
`shred`: `RESULT phase=p9-bootstrap outcome=PASS`, exit `0`, same node SPIFFE ID, new node SVID
serial `307601102364009288208173643239772829818`, new `x509pop:serialnumber:` from exchange serial
`BCBDD3380C073271FBA98985E1EB428F`. A temporary entry
(`d659045f-8cda-4309-86a9-b1dc95ad0c42`, `…/guest/p10-c1r-demo`, TTL 300) proved the in-guest
Workload API serves — `Received 1 svid after 1.634251ms`, serial `1FD3B722549E9BEF1F9B9C9C7C3CA29C`,
SAN `URI:spiffe://spike.incus.internal/guest/p10-c1r-demo` — and was deleted immediately.

### Cleanup and final state

Temporary entry deleted (`Deleted 1 entries successfully`); fetched SVID files `shred -uz`'d and
verified absent; both backups removed; `boot.autostart` returned to **unset**; one nonce minted and
consumed, now dead. Closing state: five safety fields green (`tpm_status: ok`,
`system_state_is_trusted: true`, `secure_boot_enabled: true`, root and swap `unlocked (TPM)`), two
attested nodes, exactly the two chain entries, broker `active` and listening on `:8443` at digest
`4ed87f92…fa45`, relay live, all eight instances `RUNNING`, both guests snapshot-free, guest A
attested and `Agent is healthy.`, and `user.spiffe-bootstrap` clear on every instance in both
projects.

One file on the host agent volume was deliberately and permanently changed:
`/spike/conf/agent-trust-bundle.pem`, refreshed to the server's current two-authority bundle. That is
a correction of stale state, not a new artifact, and it is recorded here rather than folded away.

### Does this close the gap, and what is case 1's verdict

**Yes — directly, and by the plan's own wording.** The plan's case-1 expectation is "Host agent
re-attests via `tpm_devid`". The corrective reboot produces exactly that, evidenced by the agent's own
`Node attestation was successful … reattestable=true` under the unchanged host node SPIFFE ID, a new
server-side SVID serial, and a 33 s elapsed cost that matches the measured physical-TPM attestation
cost. It is not inferred from the absence of a cached-SVID line; it is the positive line itself.

Two results now stand side by side, and both are kept:

| Reboot | Condition | Host-agent recovery | Against the plan's literal wording |
|---|---|---|---|
| **1st** (19:00:56Z) — the control | node SVID valid, ~35 min of life against ~75 s downtime | **persisted-SVID load**, `tpm_devid` loaded but never invoked, serial unchanged | **PARTIAL** — recovery PASS, but not `tpm_devid` re-attestation |
| **2nd** (19:26:51Z) — corrective | `agent-data.json` removed; `keys.json` initially unchanged, then rewritten by SPIRE's disk KeyManager for a new keypair | **fresh `tpm_devid` attestation**, new serial, same SPIFFE ID | **PASS** |

**Final case-1 verdict: PASS WITH FINDINGS**, on all eleven original checkpoints plus the direct
fresh-attestation requirement. C1-F1 is the Medium relay boot-ordering availability finding.
C1-F2 is the Medium stale-bootstrap-trust finding. The two reboot results remain distinct: the
first proves persisted-SVID continuity, while the corrective reboot proves fresh post-boot
`tpm_devid` attestation under the same node SPIFFE ID with a new serial. Which branch a host reboot
takes depends on the node SVID's remaining lifetime, not on the reboot itself.

Production procedures that deliberately clear persisted agent state must first pass the bootstrap
bundle validation gate. Production distribution must atomically provide overlapping current and
next authorities so CA rotation does not strand a cold agent.

**Carried forward, added to the four items above:**
5. Forcing the `tpm_devid` branch requires clearing `agent-data.json` and valid configured bootstrap
   trust. C1-F2 requires rotation-aware atomic distribution of overlapping current and next
   authorities plus a mandatory pre-delete bundle validation gate.
6. Physical-TPM attestation cost is stable at ~33 s across four independent measurements spanning
   P3 and P10.

# P4 Evidence — Standard Workload API Baseline (pre-Broker control)

**Captured:** 2026-08-16 16:15 PDT
**Host:** `ovh-incusos`, SPIRE `1.15.2`, trust domain `spike.incus.internal`
**Decision:** **PASS. Baseline recorded. P7 may start alongside P5 and P6.**

## Scope

P4 is the control experiment. It records exactly how the **stock** Workload API behaves from the host agent, with no Broker and no custom attestor, so that P7's Broker-based results can be diffed against a known-good reference.

It also produced the single most architecturally important negative result of the spike so far: the stock Workload API **cannot serve a caller in another container**, and it fails at connection accept, before any attestation logic runs.

## Acceptance result

| Criterion | Result | Evidence |
|---|---|---|
| SVID issued with expected SPIFFE ID | PASS | Both entries served: `/spike/host-baseline` and `/spike/host-rotation-probe`. |
| Rotation ticks | PASS | 7 stream deliveries, probe SVID reissued every 22.4–29.7 s under a 60 s TTL. |
| Entries parented to the tpm_devid node | PASS | Parent ID equals the P3 node SPIFFE ID. |

## Registration entries used

Both parented to the P3 attested node:

```text
spiffe://spike.incus.internal/spire/agent/tpm_devid/fee6de975fb82fdbd3c7b7ea7e0b752412469fd0
```

| Entry ID | SPIFFE ID | X509 TTL | Selector |
|---|---|---|---|
| `c0d211a2-a438-4c02-96c3-7b32f30e90e3` | `spiffe://spike.incus.internal/spike/host-baseline` | default (1 h) | `unix:uid:0` |
| `6268d790-f603-4192-94f8-592f4e99b107` | `spiffe://spike.incus.internal/spike/host-rotation-probe` | `60` | `unix:uid:0` |

The short-TTL second entry was added so rotation could be observed inside a spike window instead of waiting 30 minutes. Full listing: [`server-entry-show.txt`](server-entry-show.txt).

Recreate command, for later phases:

```text
spire-server entry create -socketPath /tmp/spire-server/private/api.sock \
  -parentID spiffe://spike.incus.internal/spire/agent/tpm_devid/fee6de975fb82fdbd3c7b7ea7e0b752412469fd0 \
  -spiffeID spiffe://spike.incus.internal/spike/host-baseline \
  -selector unix:uid:0
```

## Positive fetch from inside the agent's namespaces

The caller was run with `incus exec` into the `spire-agent` container, so it shares the agent's PID and mount namespaces — the normal sidecar-style arrangement.

Captured output: [`workload-fetch-x509.txt`](workload-fetch-x509.txt).

```text
Received 2 svids after 1.958198ms

SPIFFE ID:		spiffe://spike.incus.internal/spike/host-rotation-probe
SVID Valid After:	2026-08-16 23:06:35 +0000 UTC
SVID Valid Until:	2026-08-16 23:07:45 +0000 UTC
CA #1 Valid After:	2026-08-16 22:03:53 +0000 UTC
CA #1 Valid Until:	2026-08-17 22:04:03 +0000 UTC

SPIFFE ID:		spiffe://spike.incus.internal/spike/host-baseline
SVID Valid After:	2026-08-16 23:06:35 +0000 UTC
SVID Valid Until:	2026-08-17 00:06:45 +0000 UTC
```

Two baseline numbers worth contrasting with P3:

| Operation | Cost |
|---|---|
| Node attestation (physical TPM) | ~33.5 s |
| Workload API SVID fetch (cached) | ~1.9 ms |

The TPM is on the node-identity path only. Once the agent holds its SVID, workload identity issuance is roughly four orders of magnitude cheaper. Any design that would push TPM operations onto the per-workload path is giving up that property.

Observed TTL behaviour: the 60 s entry produced a 70 s validity window and the default entry produced 1 h 10 s, so SPIRE adds a 10-second clock-skew margin on both ends. The agent reported `ttl=47.78` and `ttl=3587.78` seconds remaining at fetch time.

## Selectors the agent actually observed

From the agent log ([`spire-agent-console.log.txt`](spire-agent-console.log.txt)):

```text
DEBU PID attested to have selectors  pid=45
     selectors="[type:\"unix\" value:\"uid:0\" type:\"unix\" value:\"gid:0\"]"
     subsystem_name=workload_attestor
DEBU Fetched X.509 SVID  count=2 method=FetchX509SVID pid=45 registered=true
     service=WorkloadAPI spiffe_id="spiffe://spike.incus.internal/spike/host-rotation-probe" ttl=47.779658063
DEBU Fetched X.509 SVID  count=2 method=FetchX509SVID pid=45 registered=true
     service=WorkloadAPI spiffe_id="spiffe://spike.incus.internal/spike/host-baseline" ttl=3587.779642293
```

Only `unix:uid` and `unix:gid` were produced. The richer `unix:path`, `unix:sha256`, `unix:supplementary_gids` selectors require `discover_workload_path = true` in the `unix` attestor's `plugin_data`, which this baseline deliberately did not set.

**Baseline for P7 diffing:** with the stock `unix` attestor, the entire identity decision for a host-side workload rests on two numbers, uid and gid, resolved from the socket peer. That is the weak selector surface the Incus-aware attestor is meant to replace with authoritative instance state.

## Cross-container access fails at accept

The important control result. A caller was run from a **different** container, `spike-p3-stage`, which mounts the same volume and therefore sees the same socket. The `spire-agent` binary was copied out of the agent image so the client was byte-identical.

Socket permissions and caller identity were not the obstacle:

```text
srwxrwxrwx 1 root root 0 Aug 16 22:50 api.sock
uid=0(root) gid=0(root) groups=0(root)
```

Client result:

```text
rpc error: code = Unavailable desc = connection error: desc = "transport: failed to write client preface:
write unix @->/spike/run/api.sock: write: broken pipe"
```

Agent-side reason:

```text
WARN Connection failed during accept  error="could not resolve caller information" subsystem_name=endpoints
```

The connection is dropped during `accept`, before any workload attestation. The agent takes the peer PID from `SO_PEERCRED` and resolves it in its **own** PID namespace; a peer in a different container's PID namespace cannot be resolved, so the agent refuses to talk at all.

### Why this matters for the architecture

This is empirical confirmation of the design premise carried since the original evaluation:

1. **Sharing the Workload API socket does not extend identity to neighbours.** Making the socket reachable is necessary but nowhere near sufficient. It fails closed, which is the correct behaviour, but it means the host agent cannot serve container or VM workloads it cannot see.
2. **A transparent socket proxy cannot fix this correctly.** A proxy would become the peer, and the agent would then resolve the *proxy's* credentials. The original workload's identity would be replaced by the proxy's, which is precisely the failure mode the evaluation rejected.
3. **Therefore the Broker API path is load-bearing, not a convenience.** Guest and neighbour identity must be requested *on behalf of* a workload with an explicit, independently verifiable reference — the `AttestReference` plus Incus-state design — rather than inferred from a socket peer.
4. **The guest-local agent end state is consistent with this.** A guest-local agent serves the standard Workload API inside its own namespaces, where peer resolution works normally, and only the guest's *node* identity crosses the boundary.

The failure mode also gives P7 a precise thing to diff against: any Broker-based flow must produce identity for a caller that the stock path rejects with `could not resolve caller information`.

## Rotation behaviour

Captured stream: [`svid-rotation-watch.log.txt`](svid-rotation-watch.log.txt), produced by `spire-agent api watch` running for 2 m 54 s.

Seven deliveries. The 60 s-TTL probe was reissued on every one; the 1 h baseline SVID was never reissued.

| Delivery | Probe `Valid After` | Gap since previous delivery |
|---|---|---|
| 1 | 23:09:18 | — (initial, 1.9 ms) |
| 2 | 23:09:46 | 22.44 s |
| 3 | 23:10:11 | 25.32 s |
| 4 | 23:10:41 | 29.46 s |
| 5 | 23:11:06 | 24.71 s |
| 6 | 23:11:35 | 29.73 s |
| 7 | 23:12:00 | 24.56 s |

Mean gap 26.0 s against a 70 s validity window, so renewal happens at roughly half of remaining lifetime with jitter, and the stream pushes the new SVID to the subscriber immediately.

Throughout all seven deliveries the CA stayed constant:

```text
CA #1 Valid After:  2026-08-16 22:03:53 +0000 UTC
CA #1 Valid Until:  2026-08-17 22:04:03 +0000 UTC
```

That is the P2 authority `bb360028cd05a378d3ed0ef4fac03f6fb97d59d8`. No authority rotation has occurred yet; with a 24 h CA TTL it remains expected later in the spike.

**Baseline for P7:** rotation is per-entry and driven by entry TTL, the stream delivers all of a caller's SVIDs on every update, and a long-TTL SVID is not disturbed when a short-TTL sibling rotates.

## Revocation latency

After deleting both entries, the agent kept serving the cached SVIDs for a short window:

```text
immediately after delete : Received 2 svids after 1.840834ms
t+05s                    : rpc error: code = PermissionDenied desc = no identity issued
t+10s … t+30s            : rpc error: code = PermissionDenied desc = no identity issued
```

So entry deletion propagates to the agent in under five seconds here, consistent with the agent's default entry sync interval, but it is **not** instantaneous and the agent will serve a valid, already-issued SVID in the gap. Two consequences for the architecture:

- Deleting a registration entry is not a revocation primitive. Short TTLs, not entry deletion, bound the exposure window.
- `PermissionDenied: no identity issued` is the correct steady state for an unregistered caller, so it is a useful health signal to distinguish "not registered" from "cannot resolve caller".

## Commands exercised

```text
spire-server entry create -parentID <node> -spiffeID spiffe://spike.incus.internal/spike/host-baseline -selector unix:uid:0
spire-server entry create -parentID <node> -spiffeID spiffe://spike.incus.internal/spike/host-rotation-probe -selector unix:uid:0 -x509SVIDTTL 60
spire-server entry show
spire-server entry delete -entryID <id>
spire-server entry count ; spire-server agent count

incus exec ovh-incusos:spire-agent -- /opt/spire/bin/spire-agent api fetch x509 -socketPath /spike/run/api.sock
incus exec ovh-incusos:spire-agent -- /opt/spire/bin/spire-agent api watch  -socketPath /spike/run/api.sock

# cross-container attempt
incus file pull ovh-incusos:spire-agent/opt/spire/bin/spire-agent /tmp/spire-agent-bin
incus file push /tmp/spire-agent-bin ovh-incusos:spike-p3-stage/usr/local/bin/spire-agent --mode 0755
incus exec ovh-incusos:spike-p3-stage -- /usr/local/bin/spire-agent api fetch x509 -socketPath /state/run/api.sock
```

## Cleanup and state

- Both test entries deleted, per the plan's P4 cleanup. `entry count` is back to `0`, `agent count` is `1`.
- The attested node is untouched and still healthy.
- No TPM interaction occurred in this phase; the DevID path was not exercised again.
- Retained deliberately: the `spire-agent` binary copied into `spike-p3-stage` at `/usr/local/bin/spire-agent`. It is a useful Workload API client for later phases and carries no credentials.

## Handoff to P5, P6, P7

Baseline facts P7 must be diffed against:

| Property | Stock Workload API baseline |
|---|---|
| Caller in agent's namespaces | served, ~1.9 ms |
| Caller in another container | rejected at accept: `could not resolve caller information` |
| Selector surface | `unix:uid`, `unix:gid` only, unless `discover_workload_path` is enabled |
| Rotation | per-entry TTL, renewal at ~50 % of remaining life, pushed over the stream |
| TTL margin | +10 s clock skew on each end |
| Unregistered caller | `PermissionDenied: no identity issued` |
| Entry deletion propagation | under 5 s, cached SVID served in the gap |
| CA authority during phase | `bb360028cd05a378d3ed0ef4fac03f6fb97d59d8`, unchanged |

P5 and P6 are Incus-side work with no TPM dependency and can proceed independently. P7 now has a concrete reference point: it must produce a verifiable identity for exactly the caller class that this baseline refuses.

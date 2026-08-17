# P7 — Broker API integration, live run — 2026-08-17 01:51–01:58 UTC on `ovh-incusos` (`ns1001912.ip-147-135-105.us`, Incus server 7.3, x86_64)

Companion document: [`BROKER_BRIEF.md`](./BROKER_BRIEF.md) (source-cited contract, not rewritten here).

## Scope

Deploy the external `incus` WorkloadAttestor and the experimental Broker API onto the live
`spire-agent` container, prove the positive path end to end, exercise every failure-isolation
case named in `SPIKE_PLAN.md` lines 198–214, diff against the P4 Workload API baseline, and
restore a healthy agent.

In scope: agent config, plugin delivery, credential placement, registration entries, Broker
RPC transcripts, failure isolation, cleanup.

Out of scope: guest-facing nonce lifecycle (P8), any TPM operation, any host mutation, any
change to the code worktree.

Everything below was observed on the live host. Anything not directly observed is marked
`[ASSUMPTION]`.

## Acceptance result

| # | Criterion (source) | Verdict | Evidence |
|---|---|---|---|
| A1 | Plugin skeleton wired via `plugin_cmd` + `plugin_checksum` | PASS | [`agent-log-p7-startup.txt`](./agent-log-p7-startup.txt) — `Plugin loaded external=true plugin_name=incus` |
| A2 | Broker registration entry parented to the physically attested node; harness SVID from the standard Workload API | PASS | entry `270e6fb2…`; `spire-agent api fetch x509` returned `spiffe://spike.incus.internal/incus-broker` |
| A3 | Broker endpoint reachable over UDS with mandatory header | PASS | [`case-positive.txt`](./case-positive.txt) |
| A4 | Reflection behaviour confirmed | PASS | [`case-reflection.txt`](./case-reflection.txt) — works, but only via `-reflect-header` |
| A5 | **SVID issued from a UUID reference, selectors derived only by the plugin from live Incus state** | **PASS** | [`case-positive.txt`](./case-positive.txt) + [`agent-log-positive-selectors.txt`](./agent-log-positive-selectors.txt) |
| A6 | Selectors rendered with the `incus:` type prefix supplied by SPIRE | PASS | `type:"incus" value:"uuid:6d1c5ee3-…"` in the agent log |
| F-a | Unauthorized broker SPIFFE ID rejected at TLS, no gRPC status | PASS | [`case-a-unauthorized-broker.txt`](./case-a-unauthorized-broker.txt), control [`case-a-control.txt`](./case-a-control.txt) |
| F-b | Authorized broker, disallowed `type_url` → `PermissionDenied` | PASS | [`case-b-disallowed-type.txt`](./case-b-disallowed-type.txt) |
| F-c | Nonexistent UUID → no selectors, no SVID, distinguishable from a backend error | PASS | [`case-c-nonexistent-uuid.txt`](./case-c-nonexistent-uuid.txt) vs [`case-e-backend-unreachable.txt`](./case-e-backend-unreachable.txt) |
| F-d | Missing `broker.spiffe.io: true` → `InvalidArgument` | PASS | [`case-d-missing-header.txt`](./case-d-missing-header.txt) |
| F-e | Incus API unreachable → bounded failure, not a hang | PASS | [`case-e-backend-unreachable.txt`](./case-e-backend-unreachable.txt) — `Unavailable` in 6 s wall against `request_timeout = "5s"` |
| F-g | Generation mismatch (trust rule 3, frozen schema) | PASS | [`case-f-generation-mismatch.txt`](./case-f-generation-mismatch.txt) — `PermissionDenied` |
| D1 | Delivery mechanism recorded | PASS | [§ Decision D1](#decision-d1) |
| D2 | Diff against P4 baseline stated | PASS | [§ Diff against the P4 baseline](#diff-against-the-p4-baseline) |
| C1 | Test entries deleted, one attested agent, host untouched | PASS | [§ Cleanup and final state](#cleanup-and-final-state) |

Rows added by the post-fix re-verification of 2026-08-17 02:17–02:24 UTC. The original rows
above are left exactly as they were recorded; these are additional, and where they supersede
an original claim that is called out explicitly.

| # | Criterion | Verdict | Evidence |
|---|---|---|---|
| R1 | Fixed plugin deployed; on-volume SHA-256 equals `155143a1…4fca4`, verified from inside a container | PASS | [`postfix-agent-log-startup.txt`](./postfix-agent-log-startup.txt) — `Plugin loaded external=true plugin_name=incus` |
| R2 | A wrong `plugin_checksum` is actually rejected (D1's only integrity control) | PASS | [`postfix-case-checksum-mismatch.txt`](./postfix-case-checksum-mismatch.txt) — `checksums did not match`, then `Agent crashed` |
| R3 | Positive path re-proven post-fix: same six `incus:` selectors, same issued SPIFFE ID | PASS | [`postfix-case-positive.txt`](./postfix-case-positive.txt) + [`postfix-agent-log-positive-selectors.txt`](./postfix-agent-log-positive-selectors.txt) |
| R4 | **Incus HTTP 403 → `FailedPrecondition` / `incus backend authorization failed`, exactly one Incus attempt, no retry** | **PASS** | [`postfix-case-authz-403.txt`](./postfix-case-authz-403.txt) + [`postfix-agent-log-authz-403.txt`](./postfix-agent-log-authz-403.txt) |
| R5 | Transient class did not regress: black hole still `Unavailable` / `incus backend unavailable`, still bounded by `request_timeout` | PASS | [`postfix-case-blackhole.txt`](./postfix-case-blackhole.txt) — 6 s wall against `"5s"` |
| R6 | Positive path still works after the credential was swapped back | PASS | [`postfix-case-restored-after-authz.txt`](./postfix-case-restored-after-authz.txt), [`postfix-case-final-positive.txt`](./postfix-case-final-positive.txt) |
| R7 | A *trusted but under-privileged* Incus credential is indistinguishable from "instance not found" | **OBSERVED — new product risk, not an acceptance failure** | [`postfix-incus-authz-probe.txt`](./postfix-incus-authz-probe.txt) + [`postfix-case-underprivileged-cred.txt`](./postfix-case-underprivileged-cred.txt) |
| C2 | Post-fix cleanup: test entries deleted, one attested agent, host security state unchanged | PASS | [§ Post-fix cleanup and final state](#post-fix-cleanup-and-final-state) |

Rows added by the trust-rule gap-closure run of 2026-08-17 02:35–02:41 UTC. As above, nothing
earlier is rewritten; these are additional. They exist because an independent conformance audit
found three frozen rules asserted but unevidenced, and two selector values whose provenance the
existing transcripts could not distinguish from an echo of the request.

| # | Criterion | Verdict | Evidence |
|---|---|---|---|
| G1 | **Frozen trust rule 1** — two live instances sharing one `volatile.uuid` produce a hard failure, never a choice between them | PASS | [`postfix2-case-ambiguous-uuid.txt`](./postfix2-case-ambiguous-uuid.txt) + [`postfix2-agent-log-ambiguous-uuid.txt`](./postfix2-agent-log-ambiguous-uuid.txt) — `PermissionDenied`, `2 instances matched uuid` |
| G2 | **Frozen trust rule 5a** — an empty `instance_uuid` in the request is rejected before any Incus call, never a wildcard | PASS | [`postfix2-case-empty-uuid.txt`](./postfix2-case-empty-uuid.txt) + [`postfix2-agent-log-empty-uuid.txt`](./postfix2-agent-log-empty-uuid.txt) — `InvalidArgument` |
| G3 | **Frozen trust rule 5b** — a live record whose `volatile.uuid` has been unset matches nothing, including its own former UUID | PASS | same two files — empty `{}`, `selectors="[]"` |
| G4 | **Endpoint expectation** — a wrong `server` claim fails closed | PASS | [`postfix2-case-server-mismatch.txt`](./postfix2-case-server-mismatch.txt) + [`postfix2-agent-log-server-mismatch.txt`](./postfix2-agent-log-server-mismatch.txt) — `PermissionDenied` / `incus instance reference is not attestable` |
| G5 | **Frozen trust rule 2** — the `server` claim is compared against the live `GET /1.0` endpoint identity, not echoed; the matching control succeeds | PASS | [`postfix2-case-server-match.txt`](./postfix2-case-server-match.txt) + [`postfix2-agent-log-server-match.txt`](./postfix2-agent-log-server-match.txt) |
| G6 | **Derivation provenance for `project`** — a request that omits `project` entirely still yields `incus:project:spike-spiffe` | PASS | [`postfix2-selector-provenance.txt`](./postfix2-selector-provenance.txt) § 1 |
| G7 | **Derivation provenance for the record-sourced set** — `incus:name` follows an instance rename with the request byte-identical | PASS | [`postfix2-selector-provenance.txt`](./postfix2-selector-provenance.txt) § 4 |
| G8 | **Entry parentage** — both recreated entries are parented to the attested node's SPIFFE ID; the harness SVID came from the standard Workload API | PASS | [`postfix2-entry-show.txt`](./postfix2-entry-show.txt) |
| C3 | Gap-closure cleanup: throwaway instances and entries deleted, `spike-authz-probe` unmodified, one attested agent, host security state unchanged | PASS | [`postfix2-final-state.txt`](./postfix2-final-state.txt) |

**H6 is proven.** The v1.15.2 agent Broker API accepted the vendor `type_url`
`type.googleapis.com/componere.incus.v1alpha1.IncusInstanceReference`, routed it to the
external `AttestReference` attestor, and SPIRE minted an SVID from selectors the plugin read
out of live Incus. No fallback (Delegated Identity API, direct server-API minting) is needed.

## Decision D1

**Delivery: mounted volume, not a derived image.** The plugin binary was pushed to the
existing custom volume `spike-spire-agent-state` at `/spike/bin/incus-attestor`, mode `0755`.

Observed tradeoffs, not theory:

| Property | Mounted volume (chosen) | Derived image (rejected for the spike) |
|---|---|---|
| Iteration cost | One `incus file push` (~10 s) plus `incus restart`; no rebuild | Rebuild and republish the distroless image per change |
| Distroless compatibility | Works: `incus file push`/`pull` use the Incus API and need no in-container shell | Same |
| Supply chain | **Weak.** The binary is mutable data on a volume that is also writable by any holder of the volume; nothing but `plugin_checksum` binds it | Strong: image digest covers the binary |
| Actual containment observed | `plugin_checksum` is the only integrity gate, and it worked — SPIRE verified the SHA-256 before exec | Digest pinning would additionally cover the delivery path |
| Blast radius surprise | The same volume is **already attached to a second container** (`spike-p3-stage`, at `/state`). Anything with that volume can read the agent's DevID artifacts and now the Incus read-only client key | Not shared |

The volume sharing is the notable finding: it made the P4-diff experiment free (see below) but
it means the spike's plugin delivery path is co-tenanted. **For production, use the derived
image.** `[ASSUMPTION]` that a derived image is practical for IncusOS is untested here.

## Deployment

### Artifacts and checksums

| Artifact | Destination on `spire-agent` | Mode | SHA-256 |
|---|---|---|---|
| `incus-attestor` (linux/amd64, built from `cmd/incus-attestor` at `30a34ac`) | `/spike/bin/incus-attestor` | `0755` | `24151e7fbe2c80082e8295493f377b3dd2a8033c94b5800862c76c7f20e1c699` — **SUPERSEDED**, see [§ Post-fix re-verification](#post-fix-re-verification-2026-08-17) |
| `grpcurl` v1.9.3 (linux/amd64) | `/spike/bin/grpcurl` | `0755` | `62e2e4315bb70fab2e27f86c1f7738d09076a097a2dc8e0f701e386251172e40` |
| Broker + reference protoset | `/spike/incus-broker.protoset` | `0644` | built locally, see § Commands exercised |

`plugin_checksum` algorithm, exactly as `BROKER_BRIEF.md` section 4 specifies: lowercase hex
SHA-256 of the binary file, 64 hex characters, computed with `shasum -a 256 <file> | cut -d ' ' -f 1`.
Value used: `24151e7fbe2c80082e8295493f377b3dd2a8033c94b5800862c76c7f20e1c699`. SPIRE accepted
it and launched the plugin; a wrong value would have failed catalog load.

> **CORRECTED 2026-08-17 (post-fix re-verification).** The second clause was an inference, not
> an observation, and it understated the consequence. It has since been tested deliberately:
> a wrong `plugin_checksum` does not merely fail catalog load, it is **fatal to the agent
> process** — `Agent crashed`, PID 1 exits, and the container transitions to `STOPPED`. See
> [§ 2. The checksum gate is real](#2-the-checksum-gate-is-real-and-it-is-fatal-not-degrading).

### Credentials for the plugin

The P5 read-only, project-confined identity `spike-attestor-ro` was copied onto the agent
volume in a dedicated directory. **No key material appears in this journal.**

| Path on the agent | Mode | Content |
|---|---|---|
| `/spike/incus-creds/client.crt` | `0600` | `spike-attestor-ro` client certificate |
| `/spike/incus-creds/client.key` | `0600` | `spike-attestor-ro` private key (never read, never printed) |
| `/spike/incus-creds/server.crt` | `0644` | Incus server certificate, kept for reference; **not used by the final config** — see below |

### Server pinning: `server_cert_path` does not work here

First configuration used `server_cert_path = "/spike/incus-creds/server.crt"`. Every
attestation failed:

```text
attestor: instance lookup failed: attestor: backend unavailable: attestor: backend unavailable:
Get "https://147.135.105.83:8443/1.0/instances?filter=config.volatile.uuid+eq+6d1c5ee3-5b2f-4ead-8e54-db985302fbdb&project=spike-spiffe&recursion=1":
tls: failed to verify certificate: x509: certificate is valid for 127.0.0.1, ::1, not 147.135.105.83
```

Cause, verified against the certificate:

```text
X509v3 Subject Alternative Name:
    DNS:ns1001912.ip-147-135-105.us, IP Address:127.0.0.1, IP Address:0:0:0:0:0:0:0:1
```

The Incus server certificate carries no IP SAN for its own public address, so hostname
verification against an IP `server_url` can never succeed. `server_cert_fingerprint` pinning
was substituted and works:

```hcl
server_cert_fingerprint = "822b00ed474a2574d43223cbf34919b76a64946e145ec246aa4ae2e43318afdd"
```

This matches how Incus itself trusts servers. Fingerprint pinning is the correct default for
this product; `server_cert_path` is only usable when `server_url` uses the DNS name in the SAN.

### Agent configuration (sanitized; full file: [`agent.conf.p7.txt`](./agent.conf.p7.txt))

Backup of the P3 configuration was taken before any edit, to
`/spike/conf/agent.conf.p3.bak` on the volume and `/tmp/p7/agent.conf.p3.bak` locally.

```hcl
agent {
    # ... unchanged P3 settings: data_dir, server_address/port, trust_domain,
    # trust_bundle_path, socket_path = "/spike/run/api.sock" ...

    experimental {
        broker {
            # Deliberately NOT under /spike/run: SPIRE rejects a broker socket in
            # the Workload API socket's directory or a subdirectory.
            socket_path = "/spike/broker-run/broker.sock"

            # bind_address intentionally omitted -> UDS only.
            brokers = [
                {
                    id = "spiffe://spike.incus.internal/incus-broker"
                    allowed_reference_types = [
                        {
                            type_url = "type.googleapis.com/componere.incus.v1alpha1.IncusInstanceReference"
                        },
                    ]
                },
            ]
        }
    }
}

plugins {
    # ... unchanged: NodeAttestor "tpm_devid", KeyManager "disk", WorkloadAttestor "unix" ...

    WorkloadAttestor "incus" {
        plugin_cmd      = "/spike/bin/incus-attestor"
        plugin_checksum = "24151e7fbe2c80082e8295493f377b3dd2a8033c94b5800862c76c7f20e1c699"

        plugin_data {
            server_url              = "https://147.135.105.83:8443"
            client_cert_path        = "/spike/incus-creds/client.crt"
            client_key_path         = "/spike/incus-creds/client.key"
            server_cert_fingerprint = "822b00ed474a2574d43223cbf34919b76a64946e145ec246aa4ae2e43318afdd"
            default_project         = "spike-spiffe"
            request_timeout         = "5s"
        }
    }
}
```

`allow_over_tcp` was never set; `bind_address` was never set. The directory
`/spike/broker-run/` was pre-created (SPIRE was not relied on to create it).

### Startup evidence ([`agent-log-p7-startup.txt`](./agent-log-p7-startup.txt))

```text
WARN[0000] Experimental features have been enabled. Please see doc/upgrading.md ...
DEBU[0000] starting plugin        args="[/spike/bin/incus-attestor]" external=true ...
DEBU[0000] plugin started         external=true path=/spike/bin/incus-attestor pid=41 ...
DEBU[0000] incus workload attestor configured   external=true plugin_name=incus ...
INFO[0000] Plugin loaded          external=true plugin_name=incus plugin_type=WorkloadAttestor
INFO[0000] SVID loaded            spiffe_id="spiffe://spike.incus.internal/spire/agent/tpm_devid/fee6de975fb82fdbd3c7b7ea7e0b752412469fd0"
INFO[0000] Starting SPIFFE Broker Endpoint      address=/spike/broker-run/broker.sock network=unix
INFO[0000] Starting Workload and SDS APIs       address=/spike/run/api.sock network=unix
```

The agent re-attested (TPM DevID node attestation unchanged) and stayed healthy: `/live` and
`/ready` both `200`.

## Positive path

### Target instance (live Incus state, read with the admin remote)

| Field | Value |
|---|---|
| Instance | `spike-authz-probe`, project `spike-spiffe`, RUNNING |
| `volatile.uuid` | `6d1c5ee3-5b2f-4ead-8e54-db985302fbdb` |
| `volatile.uuid.generation` | `6d1c5ee3-5b2f-4ead-8e54-db985302fbdb` |

Note: for this container `volatile.uuid.generation` equals `volatile.uuid`. That is consistent
with the P6 observation that a fresh instance's generation starts equal to its UUID and only
diverges on snapshot restore.

### Registration entries created for the run

| Entry ID | SPIFFE ID | Selectors |
|---|---|---|
| `270e6fb2-8dc0-4cd1-8b2d-909b763d18c0` | `spiffe://spike.incus.internal/incus-broker` | `unix:uid:0` |
| `7781d479-5c88-438e-bd21-aeab3119a822` | `spiffe://spike.incus.internal/incus/instance/6d1c5ee3-5b2f-4ead-8e54-db985302fbdb` | `incus:uuid:6d1c5ee3-…`, `incus:project:spike-spiffe` |
| `2c17f14f-a4b9-452f-8ab5-c184cf372695` | `spiffe://spike.incus.internal/rogue-broker` | `unix:uid:0` (negative case only) |

All parented to `spiffe://spike.incus.internal/spire/agent/tpm_devid/fee6de975fb82fdbd3c7b7ea7e0b752412469fd0`.

### Request and response ([`case-positive.txt`](./case-positive.txt))

Request `Any` — UUID and project only. **No selector value was supplied by the caller.**

```json
{"reference":{"reference":{
  "@type":"type.googleapis.com/componere.incus.v1alpha1.IncusInstanceReference",
  "instanceUuid":"6d1c5ee3-5b2f-4ead-8e54-db985302fbdb",
  "project":"spike-spiffe"}}}
```

Response (DER truncated, private key redacted — the wire response does carry
`x509SvidKey`, which is why the raw transcript is sanitized):

```json
{
  "svids": [
    {
      "spiffeId": "spiffe://spike.incus.internal/incus/instance/6d1c5ee3-5b2f-4ead-8e54-db985302fbdb",
      "x509Svid": "MIICSTCCAfCgAwIBAgIQGJ6wAD+VW04LGaZMLdKUYDAKBggqhkjOPQQDAjBQMQswCQYDVQQGEwJVUzEP...<TRUNCATED-DER>",
      "x509SvidKey": "<REDACTED-PRIVATE-KEY>",
      "bundle": "MIICCzCCAbCgAwIBAgIQYcJz6tzp1gTA5Ma0yxYH/TAKBggqhkjOPQQDAjBQMQswCQYDVQQGEwJVUzEP...<TRUNCATED-DER>"
    }
  ]
}
ERROR:
  Code: DeadlineExceeded
  Message: stream terminated by RST_STREAM with error code: CANCEL
```

The trailing `DeadlineExceeded` is the client's own `-max-time` closing a server-streaming
RPC after the first response, not a failure.

The issued SPIFFE ID equals the registration entry's SPIFFE ID exactly.

### Proof the derivation is real ([`agent-log-positive-selectors.txt`](./agent-log-positive-selectors.txt))

```text
DEBU  workload attestor "unix" does not support reference attestation  error="rpc error: code = Unimplemented desc = workloadattestor(unix): AttestReference not implemented" reference_type=type.googleapis.com/componere.incus.v1alpha1.IncusInstanceReference
DEBU  attesting incus instance reference   external=true instance_uuid=6d1c5ee3-5b2f-4ead-8e54-db985302fbdb plugin_name=incus project=spike-spiffe unverified_server_claim=
DEBU  attested incus instance reference    external=true plugin_name=incus selector_count=6
DEBU  Reference attested to have selectors reference_type=type.googleapis.com/componere.incus.v1alpha1.IncusInstanceReference selectors="[type:\"incus\" value:\"uuid:6d1c5ee3-5b2f-4ead-8e54-db985302fbdb\" type:\"incus\" value:\"generation:6d1c5ee3-5b2f-4ead-8e54-db985302fbdb\" type:\"incus\" value:\"project:spike-spiffe\" type:\"incus\" value:\"type:container\" type:\"incus\" value:\"name:spike-authz-probe\" type:\"incus\" value:\"image:f005c3b83cc4ffe5b0e0a0c3fccdee6decbae5559fafce9861d9c8b3d2720a16\"]"
DEBU  Subscribing to cache changes         broker_peer="spiffe://spike.incus.internal/incus-broker" method=SubscribeToX509SVID selectors="[... same six ...]"
```

Four independent facts establish that the selectors came from live Incus and not the caller:

1. The request carried only `instanceUuid` and `project`. Four of the six selectors
   (`generation`, `type`, `name`, `image`) have **no corresponding request field at all**.
2. `incus:name:spike-authz-probe` and `incus:type:container` match the live instance record.
3. `incus:image:f005c3b8…` is the image fingerprint, obtainable only from the Incus API.
4. Pointing `server_url` at a black hole made the identical request fail (see F-e), so the
   values are read per request, not cached from configuration.

All six render with the `incus:` type prefix, which SPIRE supplies from the plugin name; the
plugin returned unprefixed `uuid:…`, `generation:…` values as `BROKER_BRIEF.md` section 4
requires.

## Failure isolation

Every case below used the identical socket, protoset, and request shape; only the one
variable under test changed.

### (a) Unauthorized broker SPIFFE ID

Client cert: a genuine, currently valid SVID for `spiffe://spike.incus.internal/rogue-broker`
(entry `2c17f14f…`), which is **not** in `brokers[]`.

Client output, verbatim ([`case-a-unauthorized-broker.txt`](./case-a-unauthorized-broker.txt)):

```text
Failed to dial target host "unix:///spike/broker-run/broker.sock": context deadline exceeded
```

**gRPC code: none.** There is no `Code:` line, because the rejection happens in the TLS
handshake before any RPC — exactly as `BROKER_BRIEF.md` section 7 predicted and marked
`[UNVERIFIED]`. This resolves that open item: grpcurl 1.9.3 surfaces the pre-RPC rejection as
a dial timeout, having retried the dial for the whole `-max-time` budget.

Agent side ([`case-a-agent-log.txt`](./case-a-agent-log.txt)): **nothing at all**, at
`log_level = "DEBUG"`. No authorizer error, no `unexpected ID`, no TLS message, no
per-attempt record.

Control, proving the only difference was identity
([`case-a-control.txt`](./case-a-control.txt)) — same directory, `svid.0` is the authorized
`incus-broker` identity, same request:

```text
      "spiffeId": "spiffe://spike.incus.internal/incus/instance/6d1c5ee3-5b2f-4ead-8e54-db985302fbdb",
  Code: DeadlineExceeded
```

### (b) Authorized broker, disallowed `type_url`

([`case-b-disallowed-type.txt`](./case-b-disallowed-type.txt))

```text
ERROR:
  Code: PermissionDenied
  Message: broker "spiffe://spike.incus.internal/incus-broker" is not allowed to use reference type "type.googleapis.com/spiffe.broker.WorkloadPIDReference"
```

Matches the predicted source string exactly. The gate fires before any attestor call: the
agent log shows no `attesting incus instance reference` line for this request.

### (c) Nonexistent UUID

Request UUID `00000000-0000-4000-8000-000000000000`, project `spike-spiffe`
([`case-c-nonexistent-uuid.txt`](./case-c-nonexistent-uuid.txt)):

```text
{}
ERROR:
  Code: DeadlineExceeded
  Message: context deadline exceeded
```

An **empty `SubscribeToX509SVIDResponse` with no `svids`**, then the stream stays open until
the client's own deadline. No error status from the server, no SVID.

Distinguishing it from a backend error is unambiguous:

| Situation | Server behaviour |
|---|---|
| Instance not found | Empty response body `{}`, stream stays open, no server error |
| Incus unreachable | `Code: Unavailable`, `incus backend unavailable`, stream terminated |
| Instance found but expectation violated | `Code: PermissionDenied`, `incus instance reference is not attestable` |

> **AMENDED 2026-08-17 (post-fix re-verification).** This table was complete for the binary
> that was deployed at the time, but that binary collapsed every backend failure — including
> an Incus authorization denial — into `Unavailable`. The deployed code now separates them.
> Two rows are added:
>
> | Situation | Server behaviour |
> |---|---|
> | Incus rejects the plugin's credential (HTTP 401/403) | `Code: FailedPrecondition`, `incus backend authorization failed`, **never retried** |
> | Plugin misconfigured (malformed body, unexpected status, TLS pin rejected) | `Code: FailedPrecondition`, `incus backend misconfigured`, **never retried** |

This is the plugin's designed mapping (missing instance → no selectors, no error) working end
to end: SPIRE mints nothing for an empty selector set.

### (d) Missing `broker.spiffe.io: true` header

([`case-d-missing-header.txt`](./case-d-missing-header.txt))

```text
ERROR:
  Code: InvalidArgument
  Message: security header missing from request
```

Verbatim match to the predicted source string.

### (e) Incus API unreachable

Simulated without touching the real Incus service: `server_url` was repointed at
`https://10.255.255.1:8443`, an unrouted address on the container's bridge that black-holes
the SYN, and the agent was restarted. `request_timeout` stayed at `"5s"`.

Client ([`case-e-backend-unreachable.txt`](./case-e-backend-unreachable.txt)):

```text
ERROR:
  Code: Unavailable
  Message: workload attestor "incus" failed: rpc error: code = Unavailable desc = workloadattestor(incus): incus backend unavailable
elapsed_seconds=6
```

Agent ([`case-e-agent-log.txt`](./case-e-agent-log.txt)):

```text
DEBU  incus attestation failed  error="attestor: instance lookup failed: attestor: backend unavailable: attestor: backend unavailable: Get \"https://10.255.255.1:8443/1.0/instances?filter=config.volatile.uuid+eq+6d1c5ee3-5b2f-4ead-8e54-db985302fbdb&project=spike-spiffe&recursion=1\": context deadline exceeded"
ERRO  workload attestor "incus" failed   error="rpc error: code = Unavailable desc = workloadattestor(incus): incus backend unavailable" reference_type=type.googleapis.com/componere.incus.v1alpha1.IncusInstanceReference
ERRO  Workload attestation failed        broker_peer="spiffe://spike.incus.internal/incus-broker" error="..." method=SubscribeToX509SVID service=spiffe.broker.API
```

**Bounded, not a hang.** 6 s wall time against a 5 s `request_timeout`; the extra second is
`incus exec` and TLS setup. The failure is `Unavailable`, which a caller can retry, and it
does not degrade any other identity: the agent stayed attested throughout.

The working `server_url` was restored and the positive case re-verified
([`case-e-restored.txt`](./case-e-restored.txt)):

```text
      "spiffeId": "spiffe://spike.incus.internal/incus/instance/6d1c5ee3-5b2f-4ead-8e54-db985302fbdb",
```

### (g) Generation mismatch — trust rule 3 of the frozen schema

Same UUID and project, but `generationUuid` set to a value that is not the live generation
([`case-f-generation-mismatch.txt`](./case-f-generation-mismatch.txt)):

```text
ERROR:
  Code: PermissionDenied
  Message: workload attestor "incus" failed: rpc error: code = PermissionDenied desc = workloadattestor(incus): incus instance reference is not attestable
```

Trust rule 3 holds: a stated `generation_uuid` that does not match live state is a rejection,
and it is distinct from "not found" (`{}`, case c). The message is deliberately non-specific —
the plugin logs the discriminating detail at debug level and never returns live Incus state to
the caller. Confirmed: the client learns only that the reference is not attestable.

## Diff against the P4 baseline

**Yes. The Broker path issued an identity for a caller class the stock Workload API refuses,
and both were observed in the same minute against the same agent.**

`spike-p3-stage` is a separate container — separate PID, network, and mount namespaces from
`spire-agent` — that happens to already mount the same volume at `/state`. It was used
unmodified as a neighbour broker client.

| Caller | API | Result |
|---|---|---|
| `spike-p3-stage` (neighbour container) | Broker API over `/state/broker-run/broker.sock` | **SVID issued**: `spiffe://spike.incus.internal/incus/instance/6d1c5ee3-5b2f-4ead-8e54-db985302fbdb` ([`case-neighbour-broker.txt`](./case-neighbour-broker.txt)) |
| `spike-p3-stage` (same container, seconds later) | Stock Workload API over `/state/run/api.sock` | **Refused**: `rpc error: code = Unavailable desc = write unix @->/spike/run/api.sock: write: broken pipe` ([`case-neighbour-workloadapi.txt`](./case-neighbour-workloadapi.txt)) |

Agent-side log for the refusal, reproducing the P4 baseline verbatim
([`agent-log-neighbour-caller-drop.txt`](./agent-log-neighbour-caller-drop.txt)):

```text
WARN  Connection failed during accept  error="could not resolve caller information" subsystem_name=endpoints
```

**The broker client does not have to live inside the agent's namespaces.** This is
architecturally decisive:

- The Workload API authenticates the caller by resolving its PID through the peer credential,
  which fails across a PID namespace boundary — the connection is dropped at accept.
- The Broker API authenticates the caller purely by the SPIFFE ID in its mTLS client
  certificate. The agent's own log confirms the distinction: broker log lines carry
  `broker_peer="spiffe://…"` and **no `pid=` field**, while Workload API lines carry `pid=51`,
  `pid=64`, `pid=92`.
- The only remaining coupling is filesystem reachability of the Unix socket. That is a
  deployment detail (shared volume, bind mount, or `bind_address` if TCP were ever enabled),
  not an identity constraint.

Consequence for the product: `incus-spiffe-broker` in P8 can be its own container with its own
lifecycle. It does not need to be co-located in the agent's namespaces, and it should not be —
co-location would give it access to the agent's DevID material for no benefit.

## Findings for the architecture

1. **Classic PID workload attestation is now a reference attestation, and it fans out to our
   plugin on every single call.** SPIRE 1.15.2 wraps ordinary Workload API requests as
   `type.googleapis.com/spiffe.broker.WorkloadPIDReference` and calls `AttestReference` on all
   attestors. Our plugin correctly answers `InvalidArgument` for a type it does not own —
   which is exactly what the SDK proto instructs — and SPIRE logs that at **ERROR** level on
   every workload attestation ([`agent-log-workloadapi-fanout.txt`](./agent-log-workloadapi-fanout.txt)):

   ```text
   ERRO  workload attestor "incus" failed   error="rpc error: code = InvalidArgument desc = workloadattestor(incus): unsupported workload reference type \"type.googleapis.com/spiffe.broker.WorkloadPIDReference\"" pid=51
   ERRO  Failed to collect all selectors    error="workload attestor \"incus\" failed: ..."
   DEBU  PID attested to have selectors     pid=51 selectors="[type:\"unix\" value:\"uid:0\" type:\"unix\" value:\"gid:0\"]"
   DEBU  Fetched X.509 SVID  count=1 method=FetchX509SVID pid=51 registered=true spiffe_id="spiffe://spike.incus.internal/incus-broker"
   ```

   It is **not fatal** — the unix selectors survive and the SVID is still issued — but the SDK
   guidance and SPIRE's own aggregator disagree about the severity, and the result is a
   permanent stream of ERROR-level log lines on a healthy system. Two implications:
   answering `Unimplemented` for foreign types would be silently skipped instead, at the cost
   of also disabling the plugin's real type; and any alerting that treats agent ERROR lines as
   actionable will misfire. **Recommend raising this upstream.** Contradiction #4 for this
   spike.

2. **`server_cert_path` is a trap against a real Incus deployment.** The Incus server
   certificate has no IP SAN for its own public address, so pinning by certificate file plus
   an IP `server_url` always fails hostname verification. Only `server_cert_fingerprint`
   works. The plugin's two-mode design saved the run; the product should default to
   fingerprint and document that `server_cert_path` requires a DNS `server_url`.

3. **An unauthorized broker is completely invisible to the agent operator.** A rejected TLS
   handshake produces zero agent log output at DEBUG. A hostile process that can reach the
   socket can retry indefinitely with no trace. This is an observability gap the product must
   close itself (for example, the broker fronting its own authenticated endpoint), because
   SPIRE will not report it.

4. **SPIRE's own documented reflection command is wrong twice over.** The brief already
   recorded that the doc example omits the mandatory client certificate flags. Live testing
   found a second problem: grpcurl ignores `-rpc-header` for the `list` and `describe` verbs,
   so the documented invocation cannot send the mandatory security header at all
   ([`case-reflection.txt`](./case-reflection.txt)):

   ```text
   Warning: The -rpc-header argument is not used with 'list' or 'describe' verb.
   Failed to list services: rpc error: code = InvalidArgument desc = security header missing from request
   ```

   The working form uses `-reflect-header`:

   ```text
   grpc.reflection.v1.ServerReflection
   grpc.reflection.v1alpha.ServerReflection
   spiffe.broker.API
   ```

5. **`grpcurl -unix` does not work; `unix://` does.** `-unix <path>` failed with
   `dial tcp: address /spike/broker-run/broker.sock: missing port in address`. The target must
   be given as `unix:///spike/broker-run/broker.sock`. Both `BROKER_BRIEF.md` and
   `spike/p7/drive-broker.sh` use the `-unix` form and need correcting before reuse.

6. **The spike's plugin delivery is co-tenanted.** `spike-spire-agent-state` is attached to
   both `spire-agent` and `spike-p3-stage`. That made the P4 diff free but means the DevID
   blobs, the Incus read-only client key, and the plugin binary are all readable from a second
   container. Acceptable for a spike; unacceptable for the product.

7. **Distroless was not an obstacle.** Every deployment and every test ran through the Incus
   API (`incus file push`, `incus exec <absolute-path>`), with no shell in either SPIRE
   container. This is a positive result for the production image posture.

## Commands exercised

```sh
# Deploy (from the macOS workstation; -p creates parent directories on the volume)
shasum -a 256 /tmp/incus-attestor-linux | cut -d ' ' -f 1
incus file push -p --mode 0755 /tmp/incus-attestor-linux   ovh-incusos:spire-agent/spike/bin/incus-attestor
incus file push -p --mode 0755 /tmp/grpcurl-linux-amd64    ovh-incusos:spire-agent/spike/bin/grpcurl
incus file push -p --mode 0600 .../client.crt              ovh-incusos:spire-agent/spike/incus-creds/client.crt
incus file push -p --mode 0600 .../client.key              ovh-incusos:spire-agent/spike/incus-creds/client.key

# Back up the P3 config before editing
incus file pull ovh-incusos:spire-agent/spike/conf/agent.conf ./agent.conf.p3.bak
incus file push --mode 0644 ./agent.conf.p3.bak ovh-incusos:spire-agent/spike/conf/agent.conf.p3.bak

# Protoset (macOS)
GO_SPIFFE_DIR="$(go mod download -json github.com/spiffe/go-spiffe/v2@v2.8.1 | jq -r .Dir)"
protoc -I "$GO_SPIFFE_DIR" -I "$REPO_ROOT/proto" --include_imports \
  --descriptor_set_out=/tmp/p7/incus-broker.protoset \
  "$GO_SPIFFE_DIR/exp/proto/spiffe/broker/api.proto" \
  "$REPO_ROOT/proto/componere/incus/v1alpha1/reference.proto"

# Live Incus state for the target instance
incus config get ovh-incusos:spike-authz-probe volatile.uuid            --project spike-spiffe
incus config get ovh-incusos:spike-authz-probe volatile.uuid.generation --project spike-spiffe

# Registration entries
incus exec ovh-incusos:spire-server -- /opt/spire/bin/spire-server entry create \
  -socketPath /tmp/spire-server/private/api.sock \
  -spiffeID spiffe://spike.incus.internal/incus-broker \
  -parentID  spiffe://spike.incus.internal/spire/agent/tpm_devid/fee6de975fb82fdbd3c7b7ea7e0b752412469fd0 \
  -selector  unix:uid:0

# Harness SVID through the standard Workload API (target directory must exist)
incus exec ovh-incusos:spire-agent -- /opt/spire/bin/spire-agent api fetch x509 \
  -socketPath /spike/run/api.sock -write /spike/broker-svid/

# Broker call (all cases differ only in cert, header, or request body)
incus exec ovh-incusos:spire-agent -- /spike/bin/grpcurl -insecure \
  -cert /spike/broker-svid/svid.0.pem -key /spike/broker-svid/svid.0.key \
  -rpc-header 'broker.spiffe.io: true' \
  -protoset /spike/incus-broker.protoset -max-time 6 \
  -d '{"reference":{"reference":{"@type":"type.googleapis.com/componere.incus.v1alpha1.IncusInstanceReference","instanceUuid":"6d1c5ee3-5b2f-4ead-8e54-db985302fbdb","project":"spike-spiffe"}}}' \
  unix:///spike/broker-run/broker.sock spiffe.broker.API/SubscribeToX509SVID

# Reflection (note -reflect-header, not -rpc-header)
incus exec ovh-incusos:spire-agent -- /spike/bin/grpcurl -insecure \
  -cert ... -key ... -reflect-header 'broker.spiffe.io: true' \
  unix:///spike/broker-run/broker.sock list

# Console log capture (ring buffer is consumed on read: always redirect to a file first)
incus console ovh-incusos:spire-agent --show-log > agent.log 2>&1
```

`spike/p7/drive-broker.sh` from the code worktree was **not** executed as-is: it is a bash
script and both SPIRE containers are distroless, so each case was driven directly through
`incus exec /spike/bin/grpcurl`. Its three-case shape (positive, missing-header, wrong-type)
was followed exactly. It needs two corrections before reuse — the `-unix` target form and the
reflection header flag (findings 5 and 4).

## Cleanup and final state

| Action | Result |
|---|---|
| Test registration entries deleted | `270e6fb2…`, `7781d479…`, `2c17f14f…` — all three `Deleted 1 entries successfully` |
| Registration entries remaining | `Found 0 entries` |
| Attested agents | `Found 1 attested agent: spiffe://spike.incus.internal/spire/agent/tpm_devid/fee6de975fb82fdbd3c7b7ea7e0b752412469fd0`, `tpm_devid`, `Can re-attest: true`, `Agent version: 1.15.2` |
| Agent health | `/live` → `200`, `/ready` → `200` |
| Host | Untouched. No reboot, no `incus admin os` command, no TPM command, no device attachment, no container or volume created or deleted |
| Code worktree | Untouched. No edit, no commit, no repo gate run |

**Configuration kept: the P7 Broker configuration is live.** `/spike/conf/agent.conf` contains
the broker block and the `incus` attestor with the working `server_cert_fingerprint` pinning.
This was deliberate — P8 needs the endpoint, the agent is verifiably healthy with it, and
reverting would require another restart cycle. The P3 configuration is preserved verbatim at
`/spike/conf/agent.conf.p3.bak` on the volume and can be restored with one `incus file push`
plus a restart.

Known cost of keeping it: finding 1 — an ERROR-level log line pair on every Workload API
attestation. Functionally harmless, cosmetically loud.

## Teardown inventory additions

On the `spike-spire-agent-state` volume (mounted at `/spike` in `spire-agent`, `/state` in
`spike-p3-stage`):

| Path | Notes |
|---|---|
| `/spike/bin/incus-attestor` | Plugin binary, 19 MB |
| `/spike/bin/grpcurl` | grpcurl v1.9.3, 24 MB |
| `/spike/incus-creds/client.crt`, `client.key` | `spike-attestor-ro` credential — **delete on teardown** |
| `/spike/incus-creds/server.crt` | Incus server certificate; unused by the final config |
| `/spike/incus-broker.protoset` | Broker + reference descriptor set |
| `/spike/broker-run/` | Broker socket directory, contains `broker.sock` and `.keep` |
| `/spike/broker-svid/` | `svid.0.pem`, `svid.0.key`, `bundle.0.pem` — **private key on disk; delete on teardown.** CORRECTED 2026-08-17: the expiry originally recorded here (`02:52 UTC`) is superseded. The trust-rule gap-closure run refetched this SVID through the standard Workload API, so the files now on disk were issued 02:35 UTC and are valid until **2026-08-17 03:35 UTC**. |
| `/spike/rogue-svid/` | `svid.{0,1}.{pem,key}` from the negative case — **private keys on disk; delete on teardown** |
| `/spike/conf/agent.conf.p3.bak` | P3 configuration backup; keep until the spike closes |

Server side: nothing to clean; all three registration entries are already deleted.

Local workstation: `/tmp/p7/` holds unsanitized working copies including the raw positive
transcript with an SVID private key. It is throwaway and never enters the journal; the copies
in this directory are sanitized.

## Handoff to P8

Established and reusable:

1. **The Broker path works.** A vendor `type_url` routes to an external `AttestReference`
   attestor and yields an SVID whose selectors come only from live Incus. No fallback is
   needed and the go/no-go discussion in §10 is not triggered.
2. **The broker can be its own container.** Authentication is by SVID SPIFFE ID, not peer
   PID. P8's `incus-spiffe-broker` should be a separate instance that reaches the broker
   socket through a mount, and must not be co-located with the agent.
3. **Endpoint contract for P8's client**, all live-verified: `unix:///spike/broker-run/broker.sock`,
   mTLS with an SVID whose ID is exactly `spiffe://spike.incus.internal/incus-broker`,
   metadata `broker.spiffe.io: true` on every RPC (and `-reflect-header` for reflection),
   `spiffe.broker.API/SubscribeToX509SVID` is server-streaming and stays open.
4. **Error taxonomy P8 must handle**: `PermissionDenied` = allowlist or trust-rule rejection
   (including generation mismatch); empty `{}` = instance not found; `Unavailable` = Incus
   backend down, retryable; `InvalidArgument` = missing security header; dial timeout with no
   gRPC code = the broker's own identity is not authorized.

   > **CORRECTED 2026-08-17 (post-fix re-verification).** This list was written against a
   > binary that mapped *every* backend failure to `Unavailable`, so it is incomplete and, on
   > the retry question, misleading. The deployed taxonomy is now:
   >
   > | gRPC code | Message | Retry? |
   > |---|---|---|
   > | `Unavailable` | `incus backend unavailable` | **yes** — transient only (refused, reset, unreachable, timeout) |
   > | `FailedPrecondition` | `incus backend authorization failed` | **never** — Incus rejected the credential (401/403) |
   > | `FailedPrecondition` | `incus backend misconfigured` | **never** — malformed body, unexpected status, TLS pin/verify rejection, empty endpoint identity |
   > | `PermissionDenied` | `incus instance reference is not attestable` | never — trust-rule rejection |
   > | `InvalidArgument` | missing security header / unsupported reference type | never |
   > | *(none)* | empty `{}` | n/a — instance not found |
   >
   > P8's client **must not** retry `FailedPrecondition`. Only `Unavailable` is retryable.
5. **Recreate before P8**: both registration entries were deleted. P8 needs the
   `incus-broker` entry (`unix:uid:0`, or a tighter selector once the broker has its own
   container and identity) and one entry per bound instance.
6. **Carry forward**: pin SPIRE by digest, keep all Broker-facing code behind one adapter, and
   rerun this acceptance set on any SPIRE bump. Finding 1 in particular is the kind of
   behaviour that can change silently between minor versions.

## Post-fix re-verification (2026-08-17)

Run window 02:17–02:24 UTC, same host `ovh-incusos`, same agent, same target instance.

### Why this happened

The live run above passed, and then an **independent QA review of the durable Go code found
two blockers** — defects in the code, not in the run. The run was therefore valid evidence
about a binary that no longer represents the product:

**Blocker 1 — retryability was not preserved across layers.** Every Incus backend failure,
including an HTTP 401/403 authorization denial, collapsed into `ErrBackendUnavailable` →
gRPC `Unavailable`. Because `Unavailable` is the retryable code, the Broker client retried up
to three times, so a flat authorization denial drove **three full attestations** against
Incus. A permanent, operator-caused condition was being treated as a transient one. The
deployed code now splits the sentinel:

| Core sentinel | Retry | gRPC code | Message |
|---|---|---|---|
| `attestor.ErrBackendUnavailable` (refused, reset, unreachable, timeout) | retryable | `Unavailable` | `incus backend unavailable` |
| `attestor.ErrBackendUnauthorized` (Incus HTTP 401/403) | **never** | `FailedPrecondition` | `incus backend authorization failed` |
| `attestor.ErrBackendPermanent` (malformed body, unexpected status, TLS pin/verify rejection, empty endpoint identity) | **never** | `FailedPrecondition` | `incus backend misconfigured` |

Attestation *policy* failures are unchanged: `ErrAmbiguousReference`, `ErrGenerationMismatch`,
`ErrEndpointMismatch` and `ErrUnusableRecord` still map to `PermissionDenied` /
`incus instance reference is not attestable`; `ErrInvalidReference` → `InvalidArgument`;
`ErrInstanceNotFound` → no selectors and no error; unknown → `Internal`.

**Blocker 2 — the broker adapter inferred a denial's source.** `internal/broker` treated a
bare `PermissionDenied` as a reference-type denial. It now carries a generic
`ErrPermissionDenied` plus a narrowly-attributed `ErrReferenceTypeDenied` that wraps it.

Also fixed in the same pass, and not observable from the live host: the pure-core purity guard
is now an exact import allowlist, the leakage test genuinely drives backend failures, and the
documentation for frozen trust rules 4 and 7 was rewritten to state plainly that they are
deployment and operational invariants rather than code-enforced ones.

The binary on the volume was stale against all of this, so its error mapping no longer matched
the code. This section redeploys and re-proves.

### 1. Redeploy

| Artifact | Destination | Mode | SHA-256 |
|---|---|---|---|
| `incus-attestor` (linux/amd64, post-fix build) | `/spike/bin/incus-attestor` | `0755` | `155143a1e93d25380d53fff2c4c39f95e07fd779713c4cfda606c61108b4fca4` |

This **supersedes** `24151e7f…` in § Artifacts and checksums.

The agent had to be stopped first: `incus file push` into the running container failed with
`text file busy`, because SPIRE holds the plugin binary open for the life of the process. The
push was then done through `spike-p3-stage`, which mounts the same volume at `/state` — the
co-tenancy recorded as finding 6 turned out to be the convenient path here, which is itself a
reminder of why it is unacceptable in production.

Verified on the volume, from inside a container:

```text
155143a1e93d25380d53fff2c4c39f95e07fd779713c4cfda606c61108b4fca4  /state/bin/incus-attestor
```

Post-fix startup ([`postfix-agent-log-startup.txt`](./postfix-agent-log-startup.txt)):

```text
DEBU[0000] incus workload attestor configured   external=true plugin_name=incus subsystem_name=incus.incus-attestor
DEBU[0000] plugin started                       external=true path=/spike/bin/incus-attestor pid=39 plugin_name=incus
INFO[0000] Plugin loaded                        external=true plugin_name=incus plugin_type=WorkloadAttestor
INFO[0000] SVID loaded                          spiffe_id="spiffe://spike.incus.internal/spire/agent/tpm_devid/fee6de975fb82fdbd3c7b7ea7e0b752412469fd0"
INFO[0000] Starting SPIFFE Broker Endpoint      address=/spike/broker-run/broker.sock network=unix
INFO[0000] Starting Workload and SDS APIs       address=/spike/run/api.sock network=unix
```

The agent re-attested through the TPM DevID node attestor to the **same** SPIFFE ID, and
`/live` and `/ready` both returned `200`.

### 2. The checksum gate is real, and it is fatal, not degrading

`plugin_checksum` is the *only* integrity control on the volume-delivery mechanism chosen in
decision D1, and the original run only inferred that it worked in the negative direction. It
was tested directly: the new binary was deployed with `plugin_checksum` deliberately set to
`0000…0000`, and the agent started.

Verbatim ([`postfix-case-checksum-mismatch.txt`](./postfix-case-checksum-mismatch.txt)):

```text
ERRO[0000] Failed to load plugin   error="failed to launch plugin: checksums did not match" external=true plugin_name=incus plugin_type=WorkloadAttestor subsystem_name=catalog
INFO[0000] Plugin unloaded         external=false plugin_name=unix plugin_type=WorkloadAttestor subsystem_name=catalog
INFO[0000] Plugin unloaded         external=false plugin_name=disk plugin_type=KeyManager subsystem_name=catalog
INFO[0000] Plugin unloaded         external=false plugin_name=tpm_devid plugin_type=NodeAttestor subsystem_name=catalog
ERRO[0000] Agent crashed           error="failed to load plugin \"incus\": failed to launch plugin: checksums did not match"
```

Three things worth recording, none of which the original run could claim:

1. **The gate fires before exec.** SPIRE hashes the file and compares before launching it, so
   a substituted binary is never executed.
2. **It fails closed, hard.** The agent does not start degraded with the `incus` attestor
   missing; it unloads every other plugin and exits. In these distroless containers SPIRE is
   PID 1, so the container itself went to `STOPPED` — the failure is loud and impossible to
   miss.
3. **This is the whole of D1's supply-chain story.** It genuinely binds the binary's content,
   and it binds nothing else: not the delivery path, not who wrote the file, not when. The
   recommendation to use a derived image for production stands unchanged.

The correct checksum was then restored and the agent started cleanly (§ 1 above).

### 3. Positive path, re-proven post-fix

Both registration entries the original run created and deleted were recreated, parented to the
same attested node:

| Entry ID | SPIFFE ID | Selectors |
|---|---|---|
| `b38f1fc6-248e-4b8e-9cf8-fe47cb23f758` | `spiffe://spike.incus.internal/incus-broker` | `unix:uid:0` |
| `eb8d592a-ccce-4a63-8520-e268466fb96f` | `spiffe://spike.incus.internal/incus/instance/6d1c5ee3-5b2f-4ead-8e54-db985302fbdb` | `incus:uuid:6d1c5ee3-…`, `incus:project:spike-spiffe` |

The harness SVID was fetched through the standard Workload API inside the agent container
(`spire-agent api fetch x509 -socketPath /spike/run/api.sock`), returning
`spiffe://spike.incus.internal/incus-broker`, and the same request body as before was driven
over the UDS with `broker.spiffe.io: true`.

Issued identity ([`postfix-case-positive.txt`](./postfix-case-positive.txt)):

```text
"spiffeId": "spiffe://spike.incus.internal/incus/instance/6d1c5ee3-5b2f-4ead-8e54-db985302fbdb"
```

Selectors ([`postfix-agent-log-positive-selectors.txt`](./postfix-agent-log-positive-selectors.txt)):

```text
DEBU  attested incus instance reference    external=true plugin_name=incus selector_count=6
DEBU  Reference attested to have selectors selectors="[type:\"incus\" value:\"uuid:6d1c5ee3-5b2f-4ead-8e54-db985302fbdb\" type:\"incus\" value:\"generation:6d1c5ee3-5b2f-4ead-8e54-db985302fbdb\" type:\"incus\" value:\"project:spike-spiffe\" type:\"incus\" value:\"type:container\" type:\"incus\" value:\"name:spike-authz-probe\" type:\"incus\" value:\"image:f005c3b83cc4ffe5b0e0a0c3fccdee6decbae5559fafce9861d9c8b3d2720a16\"]"
```

**Byte-identical to the pre-fix run**: the same six selectors in the same order, the same
image fingerprint, and the same issued SPIFFE ID. The error-contract fix changed no behaviour
on the success path, which is what a fix confined to failure mapping should look like.

### 4. NEW — an Incus authorization denial is non-retryable

This is the blocker-1 regression test on real hardware.

#### 4a. Finding first: which credential Incus actually rejects

The plan for this case was to point the plugin at the P5 `spike-bootstrap-writer` credential,
which P5 established is denied reads in project `spike-spiffe`. That was done, and it did
**not** produce a 403. The plugin reported `attestor: instance not found` and the caller got an
empty `{}` ([`postfix-case-underprivileged-cred.txt`](./postfix-case-underprivileged-cred.txt),
[`postfix-agent-log-underprivileged-cred.txt`](./postfix-agent-log-underprivileged-cred.txt)).

Probing Incus directly with the exact query the plugin issues explains why
([`postfix-incus-authz-probe.txt`](./postfix-incus-authz-probe.txt)):

| Client identity | HTTP | Body |
|---|---|---|
| `spike-attestor-ro` — trusted, project-confined read-only | `200` | `"metadata":[{ …instance record… }]` |
| `spike-bootstrap-writer` — trusted, denied reads in `spike-spiffe` | `200` | `"metadata":[]` |
| self-signed certificate, not in the Incus trust store | `403` | `{"error_code":403,"error":"not authorized"}` |

**Incus does not deny a collection query it is unauthorized for; it filters the collection
silently and returns `200` with an empty list.** `403` is reserved for a client Incus does not
recognise at all. This corrects the premise this case was written against, and it is a real
product finding — recorded as finding 8 below.

#### 4b. The 403 path, proven

The plugin was pointed at a syntactically valid client certificate that is **not** in the Incus
trust store — the realistic shape of a revoked, rotated, or never-enrolled plugin credential —
and the identical positive request was driven again.

Client, verbatim ([`postfix-case-authz-403.txt`](./postfix-case-authz-403.txt)):

```text
ERROR:
  Code: FailedPrecondition
  Message: workload attestor "incus" failed: rpc error: code = FailedPrecondition desc = workloadattestor(incus): incus backend authorization failed
elapsed_seconds=1
```

Agent, verbatim ([`postfix-agent-log-authz-403.txt`](./postfix-agent-log-authz-403.txt)):

```text
DEBU  attesting incus instance reference  external=true instance_uuid=6d1c5ee3-5b2f-4ead-8e54-db985302fbdb plugin_name=incus project=spike-spiffe
DEBU  incus attestation failed            error="attestor: instance lookup failed: attestor: backend authorization failed: authorization failed: HTTP 403" external=true plugin_name=incus
ERRO  workload attestor "incus" failed    error="rpc error: code = FailedPrecondition desc = workloadattestor(incus): incus backend authorization failed" reference_type=type.googleapis.com/componere.incus.v1alpha1.IncusInstanceReference
ERRO  Workload attestation failed         broker_peer="spiffe://spike.incus.internal/incus-broker" error="workload attestor \"incus\" failed: ..." method=SubscribeToX509SVID service=spiffe.broker.API
```

**Attempt count: exactly one.** The whole agent log for this request contains a single
`attesting incus instance reference` line. That line is emitted once per attestation, so one
line is one attestation and one Incus round trip.

Before and after, on identical inputs:

| | Pre-fix binary (`24151e7f…`) | Post-fix binary (`155143a1…`) |
|---|---|---|
| gRPC code | `Unavailable` | `FailedPrecondition` |
| Message | `incus backend unavailable` | `incus backend authorization failed` |
| Retryable by the Broker client | yes | **no** |
| Attestations per denied request | up to 3 | **1** |
| Incus round trips per denied request | up to 3 | **1** |
| Wall time | multiplied by the retry budget | 1 s |

The distinction matters beyond tidiness. Under the old mapping an operator error — a
credential that Incus will *never* accept — presented as a transient outage and was amplified
threefold against the Incus API, on every request, indefinitely. The condition it actually
describes is a precondition the deployment has not met, which is exactly what
`FailedPrecondition` means and exactly why it must not be retried.

The message is also non-specific by design, consistent with the existing trust-rule cases: the
caller learns that the backend rejected the *plugin's* credential, and nothing about live Incus
state. The discriminating detail (`HTTP 403`) stays at DEBUG in the agent log.

The read-only credential and its paths were then restored, the agent restarted, and the
positive path re-verified — same SPIFFE ID
([`postfix-case-restored-after-authz.txt`](./postfix-case-restored-after-authz.txt)).

### 5. Transient class did not regress

The black-hole case from the original run was repeated verbatim: `server_url` repointed at
`https://10.255.255.1:8443`, `request_timeout` left at `"5s"`, agent restarted.

Client ([`postfix-case-blackhole.txt`](./postfix-case-blackhole.txt)):

```text
ERROR:
  Code: Unavailable
  Message: workload attestor "incus" failed: rpc error: code = Unavailable desc = workloadattestor(incus): incus backend unavailable
elapsed_seconds=6
```

Agent ([`postfix-agent-log-blackhole.txt`](./postfix-agent-log-blackhole.txt)):

```text
DEBU  incus attestation failed          error="attestor: instance lookup failed: attestor: backend unavailable: context deadline exceeded" external=true plugin_name=incus
ERRO  workload attestor "incus" failed  error="rpc error: code = Unavailable desc = workloadattestor(incus): incus backend unavailable" reference_type=type.googleapis.com/componere.incus.v1alpha1.IncusInstanceReference
```

Identical code, identical message, identical 6 s bound against a 5 s `request_timeout`. The
retryability split did not disturb the transient class — a genuinely unreachable backend is
still `Unavailable` and still retryable.

The working `server_url` was restored and the positive path verified once more
([`postfix-case-final-positive.txt`](./postfix-case-final-positive.txt)).

### Findings added by this run

8. **An under-privileged Incus credential fails open into silence.** Incus filters collection
   queries by authorization and returns `200` with an empty list, so a plugin credential that
   has lost (or never had) read access to a project is **indistinguishable from the instance
   not existing**: no selectors, no error, an empty `{}` to the caller, and nothing above DEBUG
   in the agent log. Nothing in the plugin can detect this, because Incus does not tell it.
   Consequences the product must own:
   - Attestation silently stops working for every instance in the affected project, and the
     symptom is identical to a caller asking about a UUID that does not exist.
   - The plugin's `ErrBackendUnauthorized` path, correct as it is, will **not** catch the most
     likely real-world authorization regression — narrowing the plugin identity's project
     grants. It catches only outright non-recognition of the certificate.
   - Recommended mitigation: on configure, and periodically, have the plugin issue a probe
     against a resource it is expected to be able to read and treat an unexpectedly empty
     result as a configuration alarm. This is a health-check concern, not an attestation-path
     concern, and it should not change the per-request mapping.

9. **`plugin_checksum` failure is fatal to the agent, not to the plugin.** Recorded in § 2.
   Operationally this is the desired direction (fail closed), but it means a botched plugin
   redeploy takes the node's whole SPIRE agent down, not just reference attestation. Any
   rollout procedure must verify the checksum before restarting the agent, and a derived image
   removes the failure mode entirely.

10. **A stale plugin binary is invisible.** Nothing in the running system reports which build
    of the plugin is loaded — no version in the log line, no build stamp. The only handle is
    the configured `plugin_checksum`, which an operator must compare by hand. The product
    should log the plugin's version and commit at configure time.

### Post-fix commands exercised

```sh
# Redeploy — the agent must be stopped first (text file busy), and the push goes through the
# co-tenant container that mounts the same volume.
incus stop ovh-incusos:spire-agent
incus file push -p --mode 0755 /tmp/incus-attestor-linux ovh-incusos:spike-p3-stage/state/bin/incus-attestor
incus exec ovh-incusos:spike-p3-stage -- sha256sum /state/bin/incus-attestor
incus file push --mode 0644 ./agent.conf.correct ovh-incusos:spike-p3-stage/state/conf/agent.conf
incus start ovh-incusos:spire-agent

# Checksum-gate case: identical to the above but with plugin_checksum = "0000…0000"

# Probe which Incus responses each identity actually gets (run from the workstation)
curl -sk --cert <identity>/client.crt --key <identity>/client.key -w '\nHTTP=%{http_code}\n' \
  'https://147.135.105.83:8443/1.0/instances?filter=config.volatile.uuid+eq+6d1c5ee3-5b2f-4ead-8e54-db985302fbdb&project=spike-spiffe&recursion=1'

# Untrusted credential for the 403 case (throwaway, deleted afterwards)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout untrusted.key -out untrusted.crt -days 2 -subj '/CN=spike-untrusted-probe'

# Count Incus attempts for one request
grep -c 'attesting incus instance reference' agent.log
```

Broker calls, entry creation, SVID fetch and console capture were unchanged from
§ Commands exercised.

### Post-fix cleanup and final state

| Action | Result |
|---|---|
| Test registration entries deleted | `b38f1fc6…`, `eb8d592a…` — both `Deleted 1 entries successfully` |
| Registration entries remaining | `Found 0 entries` |
| Attested agents | `Found 1 attested agent: spiffe://spike.incus.internal/spire/agent/tpm_devid/fee6de975fb82fdbd3c7b7ea7e0b752412469fd0`, `tpm_devid`, `Can re-attest: true` |
| Agent health | `/live` → `200`, `/ready` → `200` |
| Deployed plugin | `/spike/bin/incus-attestor` = `155143a1…4fca4`; `plugin_checksum` in `/spike/conf/agent.conf` matches |
| Plugin credential | `/spike/incus-creds/` (`spike-attestor-ro`) — restored and in use |
| Throwaway credentials removed | `/spike/incus-creds-writer/` and `/spike/incus-creds-untrusted/` deleted from the volume; the untrusted key pair deleted from the workstation |
| Host security state | `tpm_status: ok`, `system_state_is_trusted: true`, `system state is fully trusted`, `secure_boot_enabled: true`, root and swap both `unlocked (TPM)` |
| Host | Untouched. No reboot, no `incus admin os` mutation, no TPM command, no device attachment, no container or volume created or deleted |
| Code worktree | Untouched. No edit, no commit, no repo gate run |

**Configuration kept: the P7 Broker configuration remains live**, now with the corrected
`plugin_checksum`. `/spike/conf/agent.conf` was **not** reverted to
`/spike/conf/agent.conf.p3.bak`, for the same reasons the original run gave — P8 needs the
endpoint and the agent is verifiably healthy with it. The P3 backup is untouched at
`/spike/conf/agent.conf.p3.bak` and still restores with one push plus a restart. The sanitized
live file is [`postfix-agent.conf.txt`](./postfix-agent.conf.txt); it differs from
[`agent.conf.p7.txt`](./agent.conf.p7.txt) in exactly one line, `plugin_checksum`.

The agent was restarted seven times over this run and re-attested through the TPM DevID node
attestor every time, to the same SPIFFE ID, with no manual intervention.

### Post-fix transcripts

| File | Contents |
|---|---|
| [`postfix-agent-log-startup.txt`](./postfix-agent-log-startup.txt) | Post-fix startup: plugin launched, SVID loaded, broker endpoint up |
| [`postfix-case-checksum-mismatch.txt`](./postfix-case-checksum-mismatch.txt) | Wrong `plugin_checksum` → `checksums did not match` → `Agent crashed` |
| [`postfix-case-positive.txt`](./postfix-case-positive.txt) | Re-proven positive path (DER truncated, key redacted) |
| [`postfix-agent-log-positive-selectors.txt`](./postfix-agent-log-positive-selectors.txt) | The same six `incus:` selectors, derived from live Incus |
| [`postfix-case-authz-403.txt`](./postfix-case-authz-403.txt) | **`FailedPrecondition` / `incus backend authorization failed`** |
| [`postfix-agent-log-authz-403.txt`](./postfix-agent-log-authz-403.txt) | Agent side of the 403 case; one attestation, one Incus attempt |
| [`postfix-incus-authz-probe.txt`](./postfix-incus-authz-probe.txt) | What Incus returns per identity: `200` full, `200` empty, `403` |
| [`postfix-case-underprivileged-cred.txt`](./postfix-case-underprivileged-cred.txt) | Denied-but-trusted credential → empty `{}`, not an error |
| [`postfix-agent-log-underprivileged-cred.txt`](./postfix-agent-log-underprivileged-cred.txt) | Agent side: `attestor: instance not found`, zero selectors |
| [`postfix-case-blackhole.txt`](./postfix-case-blackhole.txt) | Transient class unchanged: `Unavailable`, 6 s bound |
| [`postfix-agent-log-blackhole.txt`](./postfix-agent-log-blackhole.txt) | Agent side of the black-hole case |
| [`postfix-case-restored-after-authz.txt`](./postfix-case-restored-after-authz.txt) | Positive path after restoring the read-only credential |
| [`postfix-case-final-positive.txt`](./postfix-case-final-positive.txt) | Final positive verification, end of run |
| [`postfix-agent.conf.txt`](./postfix-agent.conf.txt) | Sanitized live agent configuration as left on the host |

No key material, no SVID private key and no nonce appears in any of them. The positive
transcripts carry a `<REDACTED-PRIVATE-KEY>` placeholder where the wire response carried
`x509SvidKey`, and DER blobs are truncated.

### What this changes for P8

The endpoint contract in § Handoff to P8 is unchanged. The error taxonomy in item 4 of that
section is corrected in place: **P8's Broker client must retry `Unavailable` only.**
`FailedPrecondition` in either of its two forms is a deployment fault and retrying it is
harmful — it multiplies load against Incus while having no possibility of succeeding.

Finding 8 adds one item to P8's operational checklist that no amount of client-side error
handling can substitute for: the broker cannot detect that the attestor plugin has silently
lost read access to a project, because Incus reports that state as an empty result. That has to
be caught by a health probe, and it should be caught before it presents as instances mysteriously
failing to get identities.

## Trust-rule gap closure (2026-08-17)

Run window 02:35–02:41 UTC, same host `ovh-incusos`, same agent, same deployed plugin
(`155143a1…4fca4`), no configuration change of any kind.

### Why this happened

The post-fix run above passed and the code was green. An **independent conformance audit of
the evidence** then returned three FAIL verdicts against the spike's own frozen rules and two
PARTIALs about where selector values come from. None of them said the system misbehaves; all
of them said the evidence directory did not contain an observation that the rule holds:

- **Frozen trust rule 1** (single match or fail) had a positive case and a zero-match case but
  no ambiguous case.
- **Frozen trust rule 5** (empty or absent `volatile.uuid` is a failure, never a wildcard) was
  conflated with the nonexistent-UUID case, which proves a different thing.
- **Frozen trust rule 2 / the endpoint expectation** had no `server`-mismatch case at all.
- The **`uuid` and `project` selector values** on a successful request are byte-for-byte
  present in the request, so no transcript distinguished "read from the returned record" from
  "echoed after a successful backend call".
- **Entry parentage** was written down but never shown.

This section closes those five, live, with the same socket, protoset, request shape and header
as every other case. Only the one variable under test changed each time.

### Setup

Both registration entries were recreated for this run, both parented to the physically attested
node, and the harness SVID was fetched through the **standard Workload API** inside the agent
container, not through the Broker endpoint ([`postfix2-entry-show.txt`](./postfix2-entry-show.txt)):

| Entry ID | SPIFFE ID | Selectors |
|---|---|---|
| `842b8f68-bd34-410d-8aae-f7ab5fa3ce75` | `spiffe://spike.incus.internal/incus-broker` | `unix:uid:0` |
| `ff9da0c7-2223-499f-966a-5cd6c2f62d8f` | `spiffe://spike.incus.internal/incus/instance/6d1c5ee3-…` | `incus:uuid:6d1c5ee3-…`, `incus:project:spike-spiffe` |

Both `Parent ID` fields read
`spiffe://spike.incus.internal/spire/agent/tpm_devid/fee6de975fb82fdbd3c7b7ea7e0b752412469fd0`,
which is the sole attested agent (`tpm_devid`, `Can re-attest: true`). That is the parentage
the audit asked to see rather than be told.

Two throwaway containers, `p7-dup-a` and `p7-dup-b`, were launched in project `spike-spiffe`
from the already-cached `docker.io/library/debian` image `f005c3b8…` with
`-c oci.entrypoint="sleep infinity"`. `spike-authz-probe` was **never written to**; every
`volatile.*` mutation in this section happened on a throwaway that was deleted afterwards.

### Result

| Frozen rule (REFERENCE_SCHEMA.md §3) | Verdict | gRPC code and message, verbatim | Transcript |
|---|---|---|---|
| 1. Single match or fail; never choose among ambiguous UUID matches | **PASS** | `PermissionDenied` / `workloadattestor(incus): incus instance reference is not attestable`; plugin log `attestor: ambiguous instance reference: 2 instances matched uuid cd31486d-…` | [`postfix2-case-ambiguous-uuid.txt`](./postfix2-case-ambiguous-uuid.txt), [`postfix2-agent-log-ambiguous-uuid.txt`](./postfix2-agent-log-ambiguous-uuid.txt) |
| 2. Never trust client-asserted attributes; optional claims only narrow | **PASS** | mismatch: `PermissionDenied` / `incus instance reference is not attestable`, plugin log `attestor: server "wrong-server.invalid" matches neither endpoint name "ns1001912.ip-147-135-105.us" nor fingerprint "822b00ed…"`; matching control issues the SVID | [`postfix2-case-server-mismatch.txt`](./postfix2-case-server-mismatch.txt), [`postfix2-agent-log-server-mismatch.txt`](./postfix2-agent-log-server-mismatch.txt), [`postfix2-case-server-match.txt`](./postfix2-case-server-match.txt), [`postfix2-agent-log-server-match.txt`](./postfix2-agent-log-server-match.txt) |
| 5. Empty or absent `volatile.uuid` is a failure, never a wildcard | **PASS** | empty request field: `InvalidArgument` / `workloadattestor(incus): invalid incus instance reference`, plugin log `attestor: instance uuid "" is empty or not canonical`; record with `volatile.uuid` unset: empty `{}`, `selectors="[]"`, plugin log `attestor: instance not found` | [`postfix2-case-empty-uuid.txt`](./postfix2-case-empty-uuid.txt), [`postfix2-agent-log-empty-uuid.txt`](./postfix2-agent-log-empty-uuid.txt) |
| Endpoint expectation (`server` checked against `GET /1.0`, never used to select an endpoint) | **PASS** | as row 2; no `incus:server` selector is emitted in either direction | same as row 2 |

### 1. Ambiguity is refused, and the refusal is counted

P6 established that `volatile.uuid` is writable and that Incus does **not** deduplicate it.
Setting `p7-dup-b`'s `volatile.uuid` to `p7-dup-a`'s made the filtered query return two
records:

```text
[
	"/1.0/instances/p7-dup-a?project=spike-spiffe",
	"/1.0/instances/p7-dup-b?project=spike-spiffe"
]
```

A Broker request for that UUID failed hard:

```text
ERROR:
  Code: PermissionDenied
  Message: workload attestor "incus" failed: rpc error: code = PermissionDenied desc = workloadattestor(incus): incus instance reference is not attestable
```

The plugin named the ambiguity and its size:

```text
DEBU incus attestation failed   error="attestor: ambiguous instance reference: 2 instances matched uuid cd31486d-86b5-4322-91e4-7af3638ace1f" external=true plugin_name=incus
```

The whole agent log window for that request is six lines and contains **no**
`attested incus instance reference` line and **no** `Reference attested to have selectors`
line. The plugin did not produce a selector set and then discard it; it never got that far,
and no SVID was returned.

This is the trust rule that matters most in a hostile case: a tenant who can write
`volatile.uuid` on their own instance can collide with someone else's, and a plugin that picked
either match would hand that tenant the victim's identity. It refuses instead.

### 2. Empty is not a wildcard, in both directions the rule can be broken

The rule has two failure modes and they are different. Both were driven:

**(a) Empty value in the request.** `instanceUuid: ""` is rejected before any Incus call:

```text
ERROR:
  Code: InvalidArgument
  Message: workload attestor "incus" failed: rpc error: code = InvalidArgument desc = workloadattestor(incus): invalid incus instance reference
```
```text
DEBU incus attestation failed   error="attestor: instance uuid \"\" is empty or not canonical: attestor: invalid instance reference"
```

Independently useful: Incus itself will not build the wildcard filter that a naive
implementation would send. `filter=config.volatile.uuid eq ` returns
`Error: Invalid filter: clause has no value`. So even a plugin that failed to validate would
get an error rather than a match-everything list — but the plugin does not rely on that, and
does not reach Incus at all.

**(b) Absent value on the record.** `incus config unset volatile.uuid` on the RUNNING throwaway
removed the key entirely — `incus config get` returns empty and the API record carries
`volatile.uuid.generation` with no `volatile.uuid` sibling. A request for that instance's
former UUID then matched nothing:

```text
{}
```
```text
DEBU incus attestation failed   error="attestor: instance not found"
DEBU Reference attested to have selectors   selectors="[]"
```

An instance that has lost its identity anchor is unattestable, not universally attestable. Note
the asymmetry, which is the right one: (a) is `InvalidArgument` because the caller is
malformed, (b) is the empty not-found result because the caller is well-formed and the answer
is simply "no such instance".

### 3. The `server` claim is verified, not echoed

Same request as the positive path with `server: "wrong-server.invalid"` added:

```text
ERROR:
  Code: PermissionDenied
  Message: workload attestor "incus" failed: rpc error: code = PermissionDenied desc = workloadattestor(incus): incus instance reference is not attestable
```

The plugin log line is the strongest single piece of provenance evidence in this whole
directory, because it quotes both live endpoint identities it read from `GET /1.0` in order to
reject the claim:

```text
DEBU incus attestation failed   error="attestor: server \"wrong-server.invalid\" matches neither endpoint name \"ns1001912.ip-147-135-105.us\" nor fingerprint \"822b00ed474a2574d43223cbf34919b76a64946e145ec246aa4ae2e43318afdd\": attestor: endpoint mismatch"
```

The control — the identical request with `server` set to the real
`environment.certificate_fingerprint` — issued the SVID with the same six selectors, and the
request line records the claim as `unverified_server_claim=822b00ed…`, the plugin's own naming
of the fact that an inbound claim is untrusted until compared. **No `incus:server` selector is
emitted in either case**: the claim narrows, it never becomes identity.

### 4. Where the `uuid` and `project` selector values come from

The audit's sharpest point: on a success, `incus:uuid` and `incus:project` are byte-identical
to request fields, so the existing transcripts could not exclude an echo. Four experiments,
all in [`postfix2-selector-provenance.txt`](./postfix2-selector-provenance.txt):

1. **`project` omitted entirely.** The request carried only `instanceUuid`; the agent logged
   `project=` empty on the way in, and the emitted selector set still contained
   `incus:project:spike-spiffe`. The SVID was issued and matched a registration entry whose
   selectors include `incus:project:spike-spiffe`. A value absent from the request cannot have
   been echoed from it. **This closes the `project` half outright.**
2. **`project` forged.** With `project: "default"` the lookup found nothing and the selector
   set was `[]` — a caller-supplied project is a lookup scope that can only narrow, and never
   appears as a selector on its own authority.
3. **`uuid` cannot be laundered through case.** An uppercase but otherwise identical UUID is
   refused with `InvalidArgument` and `attestor: instance uuid "6D1C5EE3-…" is empty or not
   canonical`. Recorded honestly: this means the `uuid` selector's value **cannot** be shown to
   differ from the request value by any request the plugin will accept.
4. **`incus:name` follows the record across a rename.** A throwaway was given
   `volatile.uuid=7f3a9c21-…`, queried, stopped, renamed `p7-dup-a` → `p7-renamed`, restarted,
   and queried again with a **byte-identical** request. `incus:name` changed accordingly. Both
   runs also emitted `generation:cd31486d-…` — a value not in the request, and deliberately
   *different from* the requested UUID because the generation survived the `volatile.uuid`
   rewrite.

**Finding 11 — the `uuid` selector's provenance is structural, not directly observable.**
Because a non-canonical UUID is rejected at the door, no accepted request can carry a `uuid`
that differs from the record's. The claim "read from the record" therefore rests on the
surrounding behaviour, which this run makes strong: the plugin counts matches across returned
records (§1), refuses records with no `volatile.uuid` (§2), reads the endpoint identity from
`GET /1.0` (§3), and derives every other selector — including one that differs from the
requested UUID — from the record (§4). Anyone wanting a direct observation would have to change
the code to log the record's own `volatile.uuid` before comparison; that is a product
suggestion, not a live-host experiment, and it is **not** claimed as done here.

This supersedes nothing in § Proof the derivation is real; its four facts stand. It extends the list from four selectors to five (`project` joins
`generation`, `type`, `name`, `image`) and states plainly what remains structural for the sixth.

**Selectors with no corresponding request field at all: `generation`, `type`, `name`, `image`.**
Selectors with one: `uuid` (required anchor) and `project` (optional scope, proven emitted when
the field is absent).

### Cleanup and final state

| Action | Result |
|---|---|
| Throwaway instances | `p7-dup-b` deleted; `p7-dup-a` (renamed `p7-renamed`) deleted. `incus list --project spike-spiffe` shows only `spike-authz-probe` |
| `spike-authz-probe` | Untouched. `volatile.uuid` and `volatile.uuid.generation` both still `6d1c5ee3-5b2f-4ead-8e54-db985302fbdb` |
| Registration entries deleted | `842b8f68…`, `ff9da0c7…` — both `Deleted 1 entries successfully` |
| Registration entries remaining | `Found 0 entries` |
| Attested agents | `Found 1 attested agent: spiffe://spike.incus.internal/spire/agent/tpm_devid/fee6de975fb82fdbd3c7b7ea7e0b752412469fd0`, `tpm_devid`, `Can re-attest: true`, `Agent version: 1.15.2` |
| Agent health | `/live` → `200`, `/ready` → `200` |
| Agent configuration | Unchanged. No edit, no restart, no plugin redeploy during this run |
| Host security state | `tpm_status: ok`, `system_state_is_trusted: true`, `secure_boot_enabled: true`, root and swap both `unlocked (TPM)` |
| Host | Untouched. No reboot, no `incus admin os` mutation, no TPM command, no device attachment, no volume created or deleted |
| Code worktree | Untouched. No edit, no commit, no repo gate, no Git command |

Full transcript: [`postfix2-final-state.txt`](./postfix2-final-state.txt).

### Gap-closure transcripts

| File | Contents |
|---|---|
| [`postfix2-case-ambiguous-uuid.txt`](./postfix2-case-ambiguous-uuid.txt) | Two instances, one UUID → `PermissionDenied`, no SVID |
| [`postfix2-agent-log-ambiguous-uuid.txt`](./postfix2-agent-log-ambiguous-uuid.txt) | `2 instances matched uuid …`; no selector line anywhere in the window |
| [`postfix2-case-empty-uuid.txt`](./postfix2-case-empty-uuid.txt) | Empty request UUID → `InvalidArgument`; record with `volatile.uuid` unset → empty `{}` |
| [`postfix2-agent-log-empty-uuid.txt`](./postfix2-agent-log-empty-uuid.txt) | Agent side of both halves of trust rule 5 |
| [`postfix2-case-server-mismatch.txt`](./postfix2-case-server-mismatch.txt) | Wrong `server` claim → `PermissionDenied` |
| [`postfix2-agent-log-server-mismatch.txt`](./postfix2-agent-log-server-mismatch.txt) | Rejection quoting the live `GET /1.0` server name and fingerprint |
| [`postfix2-case-server-match.txt`](./postfix2-case-server-match.txt) | Matching fingerprint control → SVID issued (DER truncated, key redacted) |
| [`postfix2-agent-log-server-match.txt`](./postfix2-agent-log-server-match.txt) | Six selectors, `unverified_server_claim=822b00ed…`, no `incus:server` selector |
| [`postfix2-selector-provenance.txt`](./postfix2-selector-provenance.txt) | `project` omitted / forged, uppercase UUID, rename before-and-after |
| [`postfix2-entry-show.txt`](./postfix2-entry-show.txt) | `entry show` with both `Parent ID`s on the attested node; Workload API SVID fetch |
| [`postfix2-final-state.txt`](./postfix2-final-state.txt) | Close-out: instances, entries, agent, health, host security state |

Appendix D scan of these eleven files: no PEM private-key block, no `nonce=`, no recovery
value. The only long-base64 hits are the truncated public X.509 SVID and bundle DER in
`postfix2-case-server-match.txt` and `postfix2-selector-provenance.txt`, both with
`<REDACTED-PRIVATE-KEY>` in place of `x509SvidKey`. One `recovery` hit exists, in
`postfix2-final-state.txt`, and it is the sentence explaining that the raw
`/os/1.0/system/security` response carries encryption recovery keys and is therefore **not**
copied into the journal; only the four non-secret state fields are quoted.

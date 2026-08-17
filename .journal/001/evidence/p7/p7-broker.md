# P7 Broker API evidence index

**Result:** **OBSERVED — PASS** on SPIRE 1.15.2 for the live P7 acceptance set. The code transcripts target commit `edab2fe`.

## Evidence map and naming reconciliation

[`SPIKE_PLAN.md`](../../SPIKE_PLAN.md#p7--broker-api-integration-experimental-surface-isolation) names `p7-broker.md` as the P7 artifact. Work began with two narrower filenames: `BROKER_BRIEF.md` for the source-derived contract and `EVIDENCE.md` for the live run. This file is the canonical `p7-broker.md` entry point. It indexes those records rather than copying their full transcripts.

| Record | Purpose |
|---|---|
| [`EVIDENCE.md`](./EVIDENCE.md) | Live deployment, commands, observations, transcript index, acceptance verdicts, cleanup, and final health |
| [`BROKER_BRIEF.md`](./BROKER_BRIEF.md) | Source-cited SPIRE 1.15.2 Broker and external-plugin contract established before the live run |
| [`FALLBACK_CONTRACT.md`](./FALLBACK_CONTRACT.md) | Experimental-risk containment and the documented but unbuilt Delegated Identity fallback |
| [`code-verification.txt`](./code-verification.txt) | Appendix C and frozen-trust-rule index for commit `edab2fe` |
| [`import-graph.txt`](./import-graph.txt) | Durable package tree and production import graph |
| [`unit-test-output.txt`](./unit-test-output.txt) | Verbatim unit-test and lint output |

## Live configuration

The sanitized configuration is [`postfix-agent.conf.txt`](./postfix-agent.conf.txt).

| Setting | Live value |
|---|---|
| Broker transport | UDS only; `bind_address` omitted |
| Broker socket | `/spike/broker-run/broker.sock` |
| Authorized broker ID | `spiffe://spike.incus.internal/incus-broker` |
| Allowed reference type | `type.googleapis.com/componere.incus.v1alpha1.IncusInstanceReference` |
| External plugin | WorkloadAttestor `incus`; `/spike/bin/incus-attestor` |
| Plugin SHA-256 pin | `155143a1e93d25380d53fff2c4c39f95e07fd779713c4cfda606c61108b4fca4` |
| Incus endpoint | `https://147.135.105.83:8443` |
| Endpoint identity pin | `822b00ed474a2574d43223cbf34919b76a64946e145ec246aa4ae2e43318afdd` |
| Default Incus project | `spike-spiffe` |
| Incus request timeout | `5s` |
| Plugin credential | `spike-attestor-ro` read-only identity; key material is not recorded |

## Manual Broker call

Every RPC sends `broker.spiffe.io: true`. Reflection uses `-reflect-header`; method calls use `-rpc-header`. Live grpcurl 1.9.3 accepted `unix:///spike/broker-run/broker.sock`; the `-unix` form did not work in this environment.

```sh
incus exec ovh-incusos:spire-agent -- /spike/bin/grpcurl -insecure \
  -cert /spike/broker-svid/svid.0.pem \
  -key /spike/broker-svid/svid.0.key \
  -rpc-header 'broker.spiffe.io: true' \
  -protoset /spike/incus-broker.protoset \
  -max-time 6 \
  -d '{"reference":{"reference":{"@type":"type.googleapis.com/componere.incus.v1alpha1.IncusInstanceReference","instanceUuid":"6d1c5ee3-5b2f-4ead-8e54-db985302fbdb","project":"spike-spiffe"}}}' \
  unix:///spike/broker-run/broker.sock \
  spiffe.broker.API/SubscribeToX509SVID
```

The protoset and SVID files already existed on the agent volume for the live run. Paths are shown; certificate and key contents are not.

## Positive result

| Observation | Result | Transcript |
|---|---|---|
| UUID reference | `6d1c5ee3-5b2f-4ead-8e54-db985302fbdb` in project `spike-spiffe` | [`postfix-case-positive.txt`](./postfix-case-positive.txt) |
| Issued identity | `spiffe://spike.incus.internal/incus/instance/6d1c5ee3-5b2f-4ead-8e54-db985302fbdb` | [`postfix-case-positive.txt`](./postfix-case-positive.txt) |
| Derived selector set | Exactly `incus:uuid`, `incus:generation`, `incus:project`, `incus:type`, `incus:name`, and `incus:image` | [`postfix-agent-log-positive-selectors.txt`](./postfix-agent-log-positive-selectors.txt) |
| Live Incus read | The configured `spike-attestor-ro` identity received HTTP 200 and the target instance record | [`postfix-incus-authz-probe.txt`](./postfix-incus-authz-probe.txt) |
| Agent after final restore | Positive issuance succeeded after restoring the read-only credential and again at the end of the run | [`postfix-case-restored-after-authz.txt`](./postfix-case-restored-after-authz.txt), [`postfix-case-final-positive.txt`](./postfix-case-final-positive.txt) |
| Registration parentage | Broker and instance entries both name the physically attested `tpm_devid` node as `Parent ID`; the harness SVID came from the standard Workload API | [`postfix2-entry-show.txt`](./postfix2-entry-show.txt) |
| Project-selector provenance | Omitting `project` still emitted `incus:project:spike-spiffe`; a forged project produced no selectors | [`postfix2-selector-provenance.txt`](./postfix2-selector-provenance.txt) |
| Endpoint expectation | The live endpoint fingerprint succeeded; `wrong-server.invalid` failed against the name and fingerprint read through `GET /1.0` | [`postfix2-case-server-match.txt`](./postfix2-case-server-match.txt), [`postfix2-agent-log-server-match.txt`](./postfix2-agent-log-server-match.txt), [`postfix2-case-server-mismatch.txt`](./postfix2-case-server-mismatch.txt), [`postfix2-agent-log-server-mismatch.txt`](./postfix2-agent-log-server-mismatch.txt) |

## Required failure-isolation cases

These are P7 exact work item 5's four required cases. `SubscribeToX509SVID` is a streaming RPC. In the nonexistent-UUID case, grpcurl first printed the empty `{}` update and then reached its own deadline while the subscription remained open; the `DeadlineExceeded` line is not an attestor-issued denial.

| Case | Observable result | gRPC code | Transcript |
|---|---|---|---|
| Unauthorized broker SPIFFE ID | TLS peer authorization prevented the RPC; grpcurl timed out while dialing | None; pre-RPC transport failure | [`case-a-unauthorized-broker.txt`](./case-a-unauthorized-broker.txt); authorized control: [`case-a-control.txt`](./case-a-control.txt) |
| Authorized broker with disallowed `type_url` | Broker allowlist rejected `WorkloadPIDReference` | `PermissionDenied` | [`case-b-disallowed-type.txt`](./case-b-disallowed-type.txt) |
| Nonexistent UUID | Empty `{}` update; no selectors and no SVID; client deadline followed on the open stream | `DeadlineExceeded` from grpcurl's deadline after the empty update | [`case-c-nonexistent-uuid.txt`](./case-c-nonexistent-uuid.txt) |
| Incus API outage | Fixed `incus backend unavailable` failure after 6 seconds against a 5-second request timeout | `Unavailable` | [`postfix-case-blackhole.txt`](./postfix-case-blackhole.txt); agent side: [`postfix-agent-log-blackhole.txt`](./postfix-agent-log-blackhole.txt) |

## Additional negative and regression cases

| Case | Observable result | gRPC code | Transcript |
|---|---|---|---|
| Missing `broker.spiffe.io: true` | Broker rejected the call before attestation | `InvalidArgument` | [`case-d-missing-header.txt`](./case-d-missing-header.txt) |
| Generation claim differs from the live record | Attestor rejected the reference | `PermissionDenied` | [`case-f-generation-mismatch.txt`](./case-f-generation-mismatch.txt) |
| Incus rejected the plugin credential with HTTP 403 | Fixed `incus backend authorization failed`; one attestation attempt | `FailedPrecondition` | [`postfix-case-authz-403.txt`](./postfix-case-authz-403.txt); agent side: [`postfix-agent-log-authz-403.txt`](./postfix-agent-log-authz-403.txt) |
| Trusted but under-privileged Incus credential | Incus returned an authorization-filtered empty list; Broker emitted `{}` and no SVID | `DeadlineExceeded` from the client's deadline after the empty update | [`postfix-case-underprivileged-cred.txt`](./postfix-case-underprivileged-cred.txt); Incus response comparison: [`postfix-incus-authz-probe.txt`](./postfix-incus-authz-probe.txt) |
| Two live records share one `volatile.uuid` | Incus returned both records; the plugin reported the count and chose neither | `PermissionDenied` | [`postfix2-case-ambiguous-uuid.txt`](./postfix2-case-ambiguous-uuid.txt); agent side: [`postfix2-agent-log-ambiguous-uuid.txt`](./postfix2-agent-log-ambiguous-uuid.txt) |
| Empty request UUID | The plugin rejected the reference before an Incus call | `InvalidArgument` | [`postfix2-case-empty-uuid.txt`](./postfix2-case-empty-uuid.txt); agent side: [`postfix2-agent-log-empty-uuid.txt`](./postfix2-agent-log-empty-uuid.txt) |
| Live record has no `volatile.uuid` | A request for the record's former UUID matched nothing; no selectors or SVID | `DeadlineExceeded` from the client's deadline after the empty update | [`postfix2-case-empty-uuid.txt`](./postfix2-case-empty-uuid.txt); agent side: [`postfix2-agent-log-empty-uuid.txt`](./postfix2-agent-log-empty-uuid.txt) |
| Wrong endpoint `server` expectation | The claim matched neither endpoint name nor certificate fingerprint returned by `GET /1.0` | `PermissionDenied` | [`postfix2-case-server-mismatch.txt`](./postfix2-case-server-mismatch.txt); agent side: [`postfix2-agent-log-server-mismatch.txt`](./postfix2-agent-log-server-mismatch.txt); matching control: [`postfix2-case-server-match.txt`](./postfix2-case-server-match.txt) |
| Uppercase, non-canonical UUID | The plugin rejected the client value before lookup | `InvalidArgument` | [`postfix2-selector-provenance.txt`](./postfix2-selector-provenance.txt) |
| Forged project | The asserted project narrowed lookup to no record; it never became a selector | `DeadlineExceeded` from the client's deadline after the empty update | [`postfix2-selector-provenance.txt`](./postfix2-selector-provenance.txt) |
| Wrong `plugin_checksum` | SPIRE refused the plugin and exited the agent | None; no Broker RPC ran | [`postfix-case-checksum-mismatch.txt`](./postfix-case-checksum-mismatch.txt) |

## Acceptance and containment

| Requirement | Evidence result |
|---|---|
| SVID issued from a UUID reference | **OBSERVED — PASS.** See the positive result above. |
| Selectors derived by the plugin from live Incus state | **OBSERVED — PASS.** The live record changed `incus:name` under a byte-identical request; an omitted project was supplied from the record lookup; endpoint mismatch and match cases show that `server` only narrows; the UUID path rejects non-canonical input and refuses ambiguous or absent record UUIDs. Code tests reject any returned-record UUID mismatch. See [`postfix2-selector-provenance.txt`](./postfix2-selector-provenance.txt), [`postfix2-case-server-mismatch.txt`](./postfix2-case-server-mismatch.txt), [`unit-test-output.txt`](./unit-test-output.txt), and [`code-verification.txt`](./code-verification.txt). |
| Four required failure-isolation cases | **OBSERVED — PASS (4/4).** Each case and code is indexed above. |
| Experimental-surface containment | **RECORDED.** See [`FALLBACK_CONTRACT.md`](./FALLBACK_CONTRACT.md). |

No `[ASSUMPTION]` is used in this index. Statements marked **OBSERVED** point to captured live or code-side output. The fallback is explicitly marked unbuilt in its contract.

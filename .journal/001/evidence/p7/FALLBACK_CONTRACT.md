# P7 Broker API fallback contract

**Status:** Required contingency; documented but not built.

This contract contains the experimental Broker API surface used in P7. It mirrors [P7 exact work item 6](../../SPIKE_PLAN.md#p7--broker-api-integration-experimental-surface-isolation), the [architecture-contradiction protocol](../../SPIKE_PLAN.md#10-architecture-contradiction-protocol), and risk-register row R3.

## Containment in force

| Measure | Contract | Evidence |
|---|---|---|
| Digest/checksum pinning | SPIRE may execute only the plugin binary whose SHA-256 matches `plugin_checksum`. The live value is `155143a1e93d25380d53fff2c4c39f95e07fd779713c4cfda606c61108b4fca4`. | **OBSERVED:** [`postfix-agent.conf.txt`](./postfix-agent.conf.txt) records the pin. A deliberately wrong checksum produced `checksums did not match` and `Agent crashed` in [`postfix-case-checksum-mismatch.txt`](./postfix-case-checksum-mismatch.txt); [`EVIDENCE.md`](./EVIDENCE.md) records that the agent container transitioned to `STOPPED`. |
| Single adapter isolation | All client code that touches the experimental Broker API stays in `internal/broker`. No other package may import `github.com/spiffe/go-spiffe/v2/exp/proto/spiffe/broker`. | **OBSERVED:** [`import-graph.txt`](./import-graph.txt) contains the production import graph. Only `internal/broker` imports the experimental Broker proto. |
| Upgrade regression gate | Before adopting any SPIRE version bump, replay this phase's positive UUID issuance and its four failure-isolation cases. A version bump does not pass on compilation or unit tests alone. | **REQUIRED:** [P7 item 6](../../SPIKE_PLAN.md#p7--broker-api-integration-experimental-surface-isolation), [section 9](../../SPIKE_PLAN.md#9-final-architecture-gono-go-criteria), and risk-register row R3 define this gate. [`EVIDENCE.md`](./EVIDENCE.md) records the acceptance set to replay. |

These measures implement R3's mitigation: “Digest pinning; single adapter isolation (Appendix C); P7 acceptance set as upgrade regression gate; documented Delegated Identity fallback.”

## Unbuilt fallback

If an upstream SPIRE change breaks the Broker API, the documented but unbuilt fallback is the **Delegated Identity API with broker-supplied selectors**.

This fallback weakens the architecture. In the P7 path, the broker submits a reference, and the agent's own external WorkloadAttestor derives selectors from authoritative Incus state. With the fallback, the broker would assert the selectors supplied to the Delegated Identity API. The broker would therefore become both the requester and the source of the identity attributes. That collapses the independent-attestation property that P7 proved and expands the broker's trust boundary.

The fallback is not an automatic compatibility path. A Broker API break is an H6 architecture contradiction. Record the exact version, failed hypothesis, and observed evidence; stop dependent adoption; then evaluate the Delegated Identity adapter as a go/no-go input. Do not substitute it silently. If the weaker trust split is unacceptable, the result is NO-GO, as required by sections 9 and 10 of the plan.

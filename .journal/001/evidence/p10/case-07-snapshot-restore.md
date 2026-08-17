# P10 Case 7 — Snapshot A, then restore

Live run on `ovh-incusos`, 2026-08-17 18:26–18:31 UTC. Full transcript:
[`case-07-snapshot-restore.txt`](./case-07-snapshot-restore.txt); end state in
[`wave-02-final-state.txt`](./wave-02-final-state.txt). No TPM command, no host reboot, no guest
deleted.

## Case 7

**Verdict:** **PASS, with informational state-machine behavior C7-F1.** The restore preserved
`volatile.uuid` and installed a new `volatile.uuid.generation`; the broker journal recorded the
precise generation mismatch for the outstanding pre-restore bootstrap value; the pre-restore
workload SVID expired and could not be renewed by anything left in the guest; and a fresh bootstrap
restored the *same* node SPIFFE ID with new credentials. **C7-F1 has no go/no-go effect:** the
old-generation nonce is consumed and rejected, the caller receives generic `409 conflict`, and the
durable broker log retains the precise first generation-mismatch cause correlatable by nonce ID.

**Plan expectation, verbatim (`SPIKE_PLAN.md` P10 case 7):**
> `generation_uuid` change invalidates outstanding bootstrap/exchange state; restored guest must re-bootstrap; stale in-guest SVIDs expire and are not renewable via old credentials.

**Setup:**

| Item | Value |
|---|---|
| Instance | `spike-guest-a`, `spike-spiffe`, `virtual-machine`, `Running` |
| Pre-snapshot UUID | `a955ca30-a0dc-4087-a369-37d53d389c5a` |
| Pre-snapshot generation | `c32efc7b-f3d8-4637-9818-f8906c35543a` |
| Live node before | `…/spire/agent/x509pop/incus/a955ca30-…`, serial `142664646892380702363741184904059716611`, expiry `2026-08-17 18:55:31 UTC`, `Can re-attest: true` |
| In-guest agent before | `spire-agent run -config /run/spike-p9/agent.conf`, pid 3525; `spire-agent healthcheck` → `Agent is healthy.` |
| Temporary workload entry | `9932dab6-7504-4102-88a1-f4f288bd54ce`, `spiffe://spike.incus.internal/guest/p10-c7-demo`, parent = A's node, selector `unix:uid:0`, `X509-SVID TTL 120` |
| Pre-snapshot workload SVID | SPIFFE ID `…/guest/p10-c7-demo`, serial `98770C369297D81D60A082E6D26821FA`, `notBefore Aug 17 18:26:38 2026 GMT`, `notAfter Aug 17 18:28:48 2026 GMT` |

Only the SVID's SPIFFE ID, serial and validity window were recorded; the certificate and key were
written to a tmpfs path and shredded in the same command (Appendix D).

**Action:**

1. Recorded pre-snapshot anchors, node state and agent health; created the temporary entry; fetched
   the workload SVID from the in-guest Workload API.
2. `incus snapshot create ovh-incusos:spike-guest-a p10-c7-before --project spike-spiffe`
   (stateless), then minted **one** bootstrap value for A — after the snapshot, so it belongs to the
   pre-restore generation — and staged the payload into the **broker** container over stdin at mode
   0600, because the restore would otherwise revert it away.
3. `incus snapshot restore ovh-incusos:spike-guest-a p10-c7-before --project spike-spiffe`.
4. Staged the pre-restore payload back into the guest over stdin and ran the canonical harness with
   `PAYLOAD_FILE`; then repeated the submission to locate the rejection relative to consumption.
5. Probed the pre-restore Workload API, tried to restart the agent from restored on-disk state, and
   waited past the recorded `notAfter`.
6. Re-bootstrapped with a fresh value using the canonical harness — no `PAYLOAD_FILE`, no
   `CHAIN_JQ`/`KEY_JQ`/`BUNDLE_JQ`, `EXCHANGE_RETENTION` left at its default `shred`.
7. Deleted both temporary entries, the snapshot, and every staged copy.

**Expected:** UUID preserved and generation changed (P6 §2, §3 rule 3); the outstanding value fails
closed on generation mismatch; the stale in-guest SVID expires and no old credential renews it; a
fresh bootstrap yields the same node SPIFFE ID because the ID derives from the stable UUID.

**Observed:**

*1 — Restore changed the generation and nothing else about identity.*

| Field | Before | After |
|---|---|---|
| `volatile.uuid` | `a955ca30-a0dc-4087-a369-37d53d389c5a` | `a955ca30-a0dc-4087-a369-37d53d389c5a` (**preserved**) |
| `volatile.uuid.generation` | `c32efc7b-f3d8-4637-9818-f8906c35543a` | `37443652-6cce-4135-a88e-e8248e9d2a20` (**new random**) |
| `user.spiffe-bootstrap` | 267-byte payload | reverted to unset (1 byte) |

Exactly the P6 restore behaviour. The restore also restarted the VM (`uptime -s` = `2026-08-17
18:27:24`), leaving no `spire-agent` process, no `/tmp/spire-agent/public/api.sock`, no
`/run/spike-p9` and no `/run/spike-exchange`. Because the instance *config* is part of the snapshot,
the restore reverted the bootstrap key as well — which is why the payload had to be staged outside
the guest to be testable at all.

*2 — The outstanding bootstrap value was refused; the broker journal names the generation
mismatch.* `nonce_id 44f0aeb0ff48f7358ef7c8f448beeb41`, minted 18:27:09 against generation
`c32efc7b-…`, TTL to `18:37:09Z`, never used. First submission after the restore:

```
redeem: HTTP 409
RESULT phase=p9-bootstrap outcome=ERROR reason=redeem_rejected status=409 nonce_id=44f0aeb0ff48f7358ef7c8f448beeb41 broker_reason=conflict
```

harness exit `11`. The broker's own reason, verbatim:

```
{"level":"WARN","msg":"bootstrap request denied","operation":"redeem","outcome":"denied","nonce_id":"44f0aeb0ff48f7358ef7c8f448beeb41","instance_uuid":"a955ca30-a0dc-4087-a369-37d53d389c5a","peer_address":"10.55.156.150:38556","http_status":409,"code":"conflict","reason":"nonce: instance generation changed: nonce 44f0aeb0ff48f7358ef7c8f448beeb41 was minted for an earlier generation of a955ca30-a0dc-4087-a369-37d53d389c5a"}
```

No exchange SVID and no node identity were issued. The mismatch is the whole reason: the UUID
matched, the secret matched, and the TTL had not expired.

*Informational fail-closed state-machine behavior — C7-F1 (no go/no-go effect).* Resubmitting the
same value gave `HTTP 409` again, but with a different internal reason:

```
{"level":"WARN","msg":"bootstrap request denied",…,"reason":"nonce: consume nonce 44f0aeb0ff48f7358ef7c8f448beeb41: nonce: nonce already used: id 44f0aeb0ff48f7358ef7c8f448beeb41"}
```

The first attempt consumed the old-generation nonce and then rejected it on the same request. This
is fail-closed state-machine behavior: the stale value is refused and spent. The caller receives the
same generic `409 conflict` for the generation mismatch and a later replay. The durable broker
journal retains the precise first cause — `instance generation changed` — and correlates it by
`nonce_id`; the later `nonce already used` record does not remove that earlier entry.

C7-F1 is informational and has no go/no-go effect. Neither response issues an identity. The generic
HTTP surface exposes no cause distinction to the caller, while the durable broker log preserves the
operator-facing cause without giving the caller an oracle.

*3 — The pre-restore workload SVID expired and nothing renewed it.*

- `spire-agent healthcheck …` → `Agent is unhealthy: unable to determine health`.
- `spire-agent api fetch x509 …` → verbatim:
  `rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing: dial unix /tmp/spire-agent/public/api.sock: connect: no such file or directory"`
- Restarting the agent from restored on-disk state (`agent-data.json` 3358 bytes + `bundle.pem`,
  certificates only — `AGENT_KEY_MANAGER=memory` never wrote a node key) failed verbatim with
  `Agent crashed … failed to configure plugin "x509pop": rpc error: code = InvalidArgument desc = unable to load keypair: open /run/spike-exchange/svid.pem: no such file or directory`.
- At `18:29:43Z`, 55 s past the recorded `notAfter` of `18:28:48Z`, the SVID was expired. The
  entry `9932dab6-…` was still present and unmodified at that moment, so the failure is
  **expiry plus absence of any renewal path**, not a deleted entry.
- **No revocation is claimed.** SPIRE does not revoke X509-SVIDs; the certificate simply aged out
  while every credential that could have obtained a replacement was gone — the exchange material
  shredded with its tmpfs, and the pre-restore nonce consumed by its own rejection.

*4 — Re-bootstrap restored the same node identity under a new credential.* A fresh mint
(`nonce_id 2ebc2abaf8386dfbd341c8d62d419e20`, `generation_uuid 37443652-…`) read by the guest from
its own socket, canonical harness, default retention:

```
redeem: HTTP 200
verdict: GRANTED
  resolved_generation=37443652-6cce-4135-a88e-e8248e9d2a20
  selectors=incus:uuid:a955ca30-…,incus:generation:37443652-…,incus:project:spike-spiffe,incus:type:virtual-machine,incus:name:spike-guest-a,incus:image:9eb18b1a9368…
agent: node attestation succeeded, node_spiffe_id=spiffe://spike.incus.internal/spire/agent/x509pop/incus/a955ca30-a0dc-4087-a369-37d53d389c5a
RESULT phase=p9-bootstrap outcome=PASS … exchange_retention=shred exchange_material=shredded-and-unmounted
```

exit `0`. The node SPIFFE ID is identical to the pre-restore one because it derives from the stable
`volatile.uuid`; only the `incus:generation` selector moved. The credentials behind it are new:

| | Before restore | After re-bootstrap |
|---|---|---|
| Node SPIFFE ID | `…/x509pop/incus/a955ca30-…` | `…/x509pop/incus/a955ca30-…` (same) |
| Node SVID serial | `142664646892380702363741184904059716611` | `43821240236870179814166160036431104854` |
| Node expiry | `2026-08-17 18:55:31 UTC` | `2026-08-17 19:30:01 UTC` |
| Agent process / state | pid 3525, `agent-data.json` mtime 17:55 | pid 953, `agent-data.json` mtime 18:29 |

A fresh temporary entry `98c7d29a-03ea-4b39-8441-66c9ad4fd88b`
(`spiffe://spike.incus.internal/guest/p10-c7-after`, TTL 300) was served immediately over the
standard Workload API, serial `3430816DA9B79ED3C76A4DB6BABC63D9`.

*One nuance worth being exact about.* The still-present `…/guest/p10-c7-demo` entry was also served
again after the re-bootstrap — as a **new** certificate, serial `CBD83E2AA2F3344806E6571D53D26EEB`,
not the expired `98770C369297D81D60A082E6D26821FA`. The invariant proven is about the *credential*,
not the *entry*: a registration entry survives a restore and can be granted again, but only to a
guest that has re-bootstrapped through the full broker path under the new generation. The
pre-restore certificate itself was never renewed and never reissued to its holder.

**Cleanup:** entries `9932dab6-7504-4102-88a1-f4f288bd54ce` and
`98c7d29a-03ea-4b39-8441-66c9ad4fd88b` deleted (`Deleted 1 entries successfully` each); snapshot
`p10-c7-before` deleted (exit 0); both staged payload copies `shred -uz`'d and verified absent in the
broker container and in the guest; throwaway rendered configs removed. Final state
([`wave-02-final-state.txt`](./wave-02-final-state.txt)): both guests `RUNNING`, no snapshots on
either, both `user.spiffe-bootstrap` keys clear, exactly the broker entry
`718f0f2e-1430-4ea8-9179-ae7223724f6b` and the exchange entry
`6261b897-9852-4740-a80f-2dbd05979597`, both nodes attested, guest A's Workload API `Agent is
healthy.`, host `tpm_status: ok`, `system_state_is_trusted: true`, `secure_boot_enabled: true`,
root and swap `unlocked (TPM)`.

**Carried forward:** guest A's generation is now `37443652-6cce-4135-a88e-e8248e9d2a20`. Any
bootstrap value minted before `2026-08-17T18:27:22Z` is permanently dead, and later waves must mint
fresh values.

## Secret handling

No nonce value, private key, or bearer token appears in this file or its transcript. Nonce secrets
moved only over stdin into mode-0600 files and were shredded; only nonce IDs, expiry times,
certificate serials, validity windows, payload digests, selectors and HTTP codes are recorded. The
executed Appendix D scan — nine canonical patterns, a planted positive control that fired on all
nine, three disclosed scan defects, and zero hits on the real evidence — is in
[`wave-02-final-state.txt`](./wave-02-final-state.txt) §§ 1–9.

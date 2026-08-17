## Case 9 — Deletion, then recreate same name

**Verdict:** PASS

**Setup:** Live host `ovh-incusos`, Incus `7.3`, SPIRE `1.15.2`, trust domain `spike.incus.internal`. One throwaway instance `spike-p10-c9-recycle` created in project `spike-spiffe` — the broker's configured project (`INCUS_SPIFFE_BROKER_PROJECT=spike-spiffe`), so the real, authenticated mint and redeem paths resolve it exactly as they resolve a production guest. Broker `incus-spiffe-broker.service` at sha256 `4ed87f92ca113334c2e2e60127ae00131a47273ac476dd1d2f05b8f2e463fa45`, unmodified. Guests `spike-guest-a` and `spike-guest-b` were not touched.

**Instance-type choice, stated explicitly:** this case used a **container**, not a VM. Justification: every claim under test is about the instance *identity record* and the broker's lookup keying — a new `volatile.uuid`, a stale `incus:uuid:` selector that cannot match, a nonce bound to a dead UUID, and the absence of any name-keyed lookup. None of it depends on guest tooling or an in-guest agent. P6 measured the delete+recreate transition on both instance types and recorded the same outcome each time (`EVIDENCE.md` T7, container: `c846f04c…` → `e9e6a2a0…`; V6, VM: `d6dc25da…` → `8c19cbce…`), and concluded "**Container vs VM divergence: none was observed in UUID or generation behavior.**" Deliberately, the minted nonce is **not** redeemed by a guest agent in the GEN1 pass — the whole point is that the state goes stale — which removes the only reason a VM would have been needed.

**Action:**

1. Create `spike-p10-c9-recycle`; record `volatile.uuid` and `volatile.uuid.generation` (call this **GEN1**).
2. Mint a real nonce for GEN1's UUID through the authenticated operator endpoint, and create a registration entry `incus:uuid:<GEN1 uuid>` parented to the TPM host node, mirroring the shape of the live exchange entry (`spiffe://spike.incus.internal/spire-exchange/incus/<uuid>`, X509 TTL 120). Do not redeem.
3. Delete the instance; recreate it under the **exact same name** (**GEN2**); record both keys.
4. Prove the GEN1 state does not apply to GEN2: different UUID; the old selector matches nothing; the old nonce is refused; the broker derives GEN2's own selectors; no lookup on any path is keyed by name.
5. Delete both throwaway entries and the instance; prove they are gone.

**Expected:** the plan's text for this row, verbatim: "New instance gets a new UUID; old registration entries/nonces do not apply; name-based confusion impossible because name is never an anchor."

**Observed:**

### 1–2. GEN1, its nonce, and its registration entry

Transcripts: [`case-09-01-create-gen1.txt`](case-09-01-create-gen1.txt), [`case-09-02-mint-and-entry.txt`](case-09-02-mint-and-entry.txt).

```
C9-GEN1 after create | name=spike-p10-c9-recycle project=spike-spiffe type=container status=Running
  location=none created_at=2026-08-17T17:03:50.766011664Z
  uuid=3bfe33a9-3b7f-42d8-9d8a-70d3cd754183 generation=3bfe33a9-3b7f-42d8-9d8a-70d3cd754183
```

`user.spiffe-bootstrap` was 0 bytes before the mint. The mint used the operator bearer token from `/state/auth/mint-token`, passed through a `curl --config` file built inside the broker container so it never entered argv or this transcript. `HTTP 201`, response body (no secret field, by contract):

```
{"nonce_id":"40b7edc017f09396c8acff9426c44b58","expires_at":"2026-08-17T17:14:12.993972062Z",
 "instance_uuid":"3bfe33a9-3b7f-42d8-9d8a-70d3cd754183","instance_name":"spike-p10-c9-recycle",
 "generation":"3bfe33a9-3b7f-42d8-9d8a-70d3cd754183","project":"spike-spiffe"}
```

The broker wrote the secret to the instance's own `user.spiffe-bootstrap` (`payload field names: broker_fingerprint, broker_url, nonce, nonce_id`; 267 bytes; `nonce_id` `40b7edc017f09396c8acff9426c44b58`). That payload was piped over stdin into a mode-0600 file inside the broker container for the later replay and was never printed. Registration entry created:

```
Entry ID                : 88de86e3-747f-4b67-b26a-0b3b62bf57ef
SPIFFE ID               : spiffe://spike.incus.internal/spire-exchange/incus/3bfe33a9-3b7f-42d8-9d8a-70d3cd754183
Parent ID               : spiffe://spike.incus.internal/spire/agent/tpm_devid/fee6de975fb82fdbd3c7b7ea7e0b752412469fd0
X509-SVID TTL           : 120
Selector                : incus:uuid:3bfe33a9-3b7f-42d8-9d8a-70d3cd754183
```

`entry show` reported `Found 3 entries` — the two pre-existing ones plus this throwaway.

### 3. Delete, then recreate under the exact same name

Transcript: [`case-09-03-delete-recreate.txt`](case-09-03-delete-recreate.txt).

```
$ incus delete ovh-incusos:spike-p10-c9-recycle --force --project spike-spiffe
(exit 0)
after delete: Error: Failed to fetch instance "spike-p10-c9-recycle" in project "spike-spiffe": Instance not found

$ incus launch docker:debian:trixie ovh-incusos:spike-p10-c9-recycle --project spike-spiffe …   (SAME NAME)
GEN2 after recreate | name=spike-p10-c9-recycle project=spike-spiffe type=container status=Running
  created_at=2026-08-17T17:05:06.384978959Z
  uuid=8b7a4ddc-c218-4c48-a79b-fe1f377e8734 generation=8b7a4ddc-c218-4c48-a79b-fe1f377e8734
```

| | GEN1 | GEN2 | Same? |
|---|---|---|---|
| `name` | `spike-p10-c9-recycle` | `spike-p10-c9-recycle` | **identical** |
| `project` / `type` | `spike-spiffe` / `container` | `spike-spiffe` / `container` | identical |
| `volatile.uuid` | `3bfe33a9-3b7f-42d8-9d8a-70d3cd754183` | `8b7a4ddc-c218-4c48-a79b-fe1f377e8734` | **different** |
| `volatile.uuid.generation` | `3bfe33a9-…-70d3cd754183` | `8b7a4ddc-…-fe1f377e8734` | **different** |
| `user.spiffe-bootstrap` | 267 bytes (GEN1 payload) | **0 bytes** | nothing carried over |

This reproduces P6 rows T7 and V6: delete+recreate yields a fresh `volatile.uuid`, and the fresh generation is re-equal to it. No UUID reuse.

### 4a. The old entry's selector cannot match the new instance

The GEN1 selector value resolves to nothing at all:

```
$ incus query '…/1.0/instances?recursion=1&all-projects=true&filter=config.volatile.uuid eq 3bfe33a9-3b7f-42d8-9d8a-70d3cd754183' | jq length
0
$ incus list ovh-incusos: --project spike-spiffe config.volatile.uuid=3bfe33a9-3b7f-42d8-9d8a-70d3cd754183 --format csv -c ns
(empty — zero matches)
```

Zero matches is P6 §3's not-found sentinel: the plugin returns no selectors and no SVID. Because the recreated instance's own derived selector set (below) contains `incus:uuid:8b7a4ddc-…` and nothing resembling `3bfe33a9-…`, entry `88de86e3…` could never be selected for it — the selector sets are disjoint on the anchor. Note that this holds even though the entry's *own* record was still live in SPIRE at the time: SPIRE's matching is by selector value, and the selector value now names an instance that does not exist.

### 4b. The old nonce is refused, inside its own TTL

Transcript: [`case-09-04-stale-nonce-replay.txt`](case-09-04-stale-nonce-replay.txt). The replay ran at `2026-08-17T17:05:28Z` against a nonce whose `expires_at` is `2026-08-17T17:14:12.993972062Z` — **still valid**, so the refusal isolates identity from expiry. The request body was the verbatim GEN1 payload read from the mode-0600 file; it was never printed.

```
$ curl -sS … -X POST https://10.55.156.44:8443/v1alpha1/redeem --data @/tmp/p10c9-payload.json
HTTP 409
response body verbatim:
{"error":"conflict"}
```

Broker log line, verbatim:

```
{"time":"2026-08-17T17:05:28.091409399Z","level":"WARN","msg":"bootstrap request denied","operation":"redeem",
 "outcome":"denied","nonce_id":"40b7edc017f09396c8acff9426c44b58",
 "instance_uuid":"3bfe33a9-3b7f-42d8-9d8a-70d3cd754183","peer_address":"10.55.156.44:40212",
 "http_status":409,"code":"conflict","reason":"attestor: instance not found"}
```

Three things this proves at once. The failure class is `attestor: instance not found` — the broker resolved the nonce's **bound UUID**, not the live name, and found nothing, even though an instance with that exact name was running two feet away. `outcome=denied` (not `outcome=burned`, and no `nonce_consumed_without_svid`), so this is a **pre-consumption refusal**: the stale nonce was never spent, and the failure is a clean 409 refusal rather than a burn. And the body carries the code only — `{"error":"conflict"}`, 21 bytes — with the diagnostic reason confined to the log.

### 4c. What the broker's attestor derives for the NEW instance

Transcript: [`case-09-06-gen2-derivation.txt`](case-09-06-gen2-derivation.txt). A second throwaway entry (`346e448d-0013-4a2d-b6d6-aee4134f2329`, selector `incus:uuid:8b7a4ddc-…`) was created so a real redemption could complete end to end. Mint for GEN2 returned `HTTP 201`; redeem returned `HTTP 200`. The success response carries exchange private-key material, so it was **never** printed: only an explicit whitelist of non-secret field names was grepped out of it, and the response file and the payload file were removed immediately (`ls: cannot access …: No such file or directory` for both).

```
"instance_uuid":"8b7a4ddc-c218-4c48-a79b-fe1f377e8734"
"instance_name":"spike-p10-c9-recycle"
"generation":"8b7a4ddc-c218-4c48-a79b-fe1f377e8734"
"project":"spike-spiffe"
"exchange_spiffe_id":"spiffe://spike.incus.internal/spire-exchange/incus/8b7a4ddc-c218-4c48-a79b-fe1f377e8734"
"selectors":["incus:uuid:8b7a4ddc-c218-4c48-a79b-fe1f377e8734",
             "incus:generation:8b7a4ddc-c218-4c48-a79b-fe1f377e8734",
             "incus:project:spike-spiffe","incus:type:container",
             "incus:name:spike-p10-c9-recycle",
             "incus:image:f005c3b83cc4ffe5b0e0a0c3fccdee6decbae5559fafce9861d9c8b3d2720a16"]
```

The reused name appears exactly once, as `incus:name:spike-p10-c9-recycle` — a **derived output** read back out of the Incus record, never an input to any lookup. The identity the chain would grant is keyed entirely by the new UUID: `spiffe://…/spire-exchange/incus/8b7a4ddc-…`, which is a different SPIFFE ID from the GEN1 entry's `…/spire-exchange/incus/3bfe33a9-…`. Two instances sharing one name are two different SPIFFE identities.

### 4d. No lookup anywhere is keyed by name

Transcript: [`case-09-05-no-name-lookup.txt`](case-09-05-no-name-lookup.txt). Three attempts to mint for the recreated instance **by name**, all refused with `HTTP 400 {"error":"invalid_request"}`; broker log reasons verbatim:

| Request body | Log `reason` |
|---|---|
| `{"instance_name":"spike-p10-c9-recycle","project":"spike-spiffe"}` | `decode request body: json: unknown field "instance_name"` |
| `{"name":"spike-p10-c9-recycle","project":"spike-spiffe"}` | `decode request body: json: unknown field "name"` |
| `{"project":"spike-spiffe"}` | `instance_uuid is required` |

The mint API has no name field to reject a wrong name with — it has no name field at all, and the strict decoder refuses one outright. The name is only ever produced, never consumed: the mint *response* reports `instance_name` as the address the broker resolved from the UUID before writing the bootstrap key, and the redeem response reports it as a derived selector. Combined with 4b — where a live instance of the right name was ignored because the nonce's UUID was dead — name-based confusion has no path to exploit.

**Cleanup:** Transcript [`case-09-07-cleanup.txt`](case-09-07-cleanup.txt).

- GEN2's `user.spiffe-bootstrap` was already 0 bytes after its successful redemption (the broker clears it on commit); the explicit `incus config unset` confirmed there was nothing left to clear: `Error: Can't unset key 'user.spiffe-bootstrap', it's not currently set`.
- Both throwaway registration entries deleted: `Deleted entry with ID: 88de86e3-747f-4b67-b26a-0b3b62bf57ef` and `Deleted entry with ID: 346e448d-0013-4a2d-b6d6-aee4134f2329`, each `Deleted 1 entries successfully`.
- Instance deleted: `incus delete ovh-incusos:spike-p10-c9-recycle --force --project spike-spiffe` (exit 0), then `Error: Failed to fetch instance "spike-p10-c9-recycle" in project "spike-spiffe": Instance not found`, and the all-projects filter for `8b7a4ddc-…` returns `0`.
- Every scratch file inside the broker container removed, including the mode-0600 GEN1 payload: `rm -f /tmp/p10c9-*` then `(no p10c9 files remain)`. The one file that survived the per-step cleanups was the first mint response, which by contract holds no secret — its shape was confirmed with values masked before deletion: `{"nonce_id":<value>,"expires_at":<value>,"instance_uuid":<value>,"instance_name":<value>,"generation":<value>,"project":<value>}`.
- **Pre-existing state untouched and verified:** `entry show` → `Found 2 entries` (`718f0f2e…` `/incus-broker`, `unix:uid:0`, TTL 3600; `655e2c68…` `/spire-exchange/incus/a955ca30-…`, `incus:uuid:a955ca30-…`, TTL 120), and `agent list` → `Found 2 attested agents` (`…/tpm_devid/fee6de975fb82fdbd3c7b7ea7e0b752412469fd0`, `…/x509pop/incus/a955ca30-a0dc-4087-a369-37d53d389c5a`), both `Can re-attest: true`. Exactly the pre-dispatch topology.
- The GEN1 nonce record (`40b7edc017f09396c8acff9426c44b58`) was never consumed and its instance no longer exists; it expired at `2026-08-17T17:14:12Z` and falls to the broker's reaper (`REAP_INTERVAL=1m`, `REAP_GRACE=2m`). Its bootstrap key died with the instance record it was written to. `[INFERENCE]` — the reaper's disposal of that specific record was not directly observed by this unit; what was observed is that the key no longer exists anywhere and the nonce is unusable (`attestor: instance not found`, and it is now also past `expires_at`).

**Secret scan:** [`secret-scan.txt`](secret-scan.txt) — nine Appendix D patterns ([`secret-scan-patterns.txt`](secret-scan-patterns.txt)) over all 15 files this unit wrote: `real-scan exit=0`, with a positive control that made all nine fire on a planted file, plus live `grep -F` comparisons against the actual operator bearer token and the host encryption/pool recovery keys (both clean), plus a clean self-scan of the report.

# P10 Case 6 — Clone (`incus copy` of A)

Live run on `ovh-incusos` (`ns1001912.ip-147-135-105.us`), 2026-08-17 18:19–18:24 UTC.
Full transcript: [`case-06-clone.txt`](./case-06-clone.txt). Every value below is quoted from it.
No TPM command was run, the host was not rebooted, and neither guest was deleted.

## Case 6

**Verdict:** **PASS.** The clone received a new `volatile.uuid` and a new
`volatile.uuid.generation`, its own guest API reported itself and not A, and its copied disk carried
no usable exchange credential and an agent that could not start. Its bootstrap redemption was bound
to the clone UUID and returned an empty SVID list. No A exchange SVID was returned to the broker,
and no A node identity was observed or changed.

**Plan expectation, verbatim (`SPIKE_PLAN.md` P10 case 6):**
> Clone's UUID/selector outcome matches P6 observation; clone cannot assume A's identity.

**Setup:**

| Item | Value |
|---|---|
| Source | `spike-guest-a`, project `spike-spiffe`, `virtual-machine`, `Running` |
| Source UUID | `a955ca30-a0dc-4087-a369-37d53d389c5a` |
| Source generation | `c32efc7b-f3d8-4637-9818-f8906c35543a` |
| Source `volatile.base_image` | `9eb18b1a93682960e9e190cd818284ad4bcaf1740be9a435630a3b1dc60acee7` |
| Snapshots on A before the case | none |
| A's `user.spiffe-bootstrap` before the case | clear (1 byte — the trailing newline of an unset value) |
| Registration entries | exactly two: broker `718f0f2e-1430-4ea8-9179-ae7223724f6b`, exchange `6261b897-9852-4740-a80f-2dbd05979597` (selector `incus:uuid:a955ca30-…`) |
| Attested nodes | `…/spire/agent/tpm_devid/fee6de97…` and `…/spire/agent/x509pop/incus/a955ca30-…`, the latter serial `142664646892380702363741184904059716611` |

**Action:**

1. `incus snapshot create ovh-incusos:spike-guest-a p10-c6-src --project spike-spiffe` — stateless
   by default, taken while A was running, confirmed `STATEFUL: NO`.
2. `incus copy ovh-incusos:spike-guest-a/p10-c6-src ovh-incusos:spike-p10-c6-clone --project spike-spiffe`.
3. Read both instance records host-side; started the clone; read its self-identity through its own
   `/dev/incus/sock`; compared the guest-visible DMI UUID on both.
4. Audited the copied disk for SPIRE material and tried to start the copied agent state with the
   harness's own rendered configuration.
5. Minted bootstrap material **for the clone UUID** through the authenticated operator endpoint and
   redeemed it **from the clone** with the canonical `guest-agent-bootstrap.sh` — no `CHAIN_JQ`,
   no hand-editing, and no claimed-identity field of any kind in the request.
6. Re-read server node list, entry list, and A's instance record.

**Expected:**

- Clone gets a fresh `volatile.uuid` and, per P6 §2, a `volatile.uuid.generation` equal to that new
  UUID (generation equals uuid "at creation and after every copy"). `type`, `project` and
  `volatile.base_image` are preserved; `created_at` is new.
- The clone's guest API reports the clone.
- No usable A exchange credential on the copied disk, because P9 runs `EXCHANGE_RETENTION=shred`
  with `AGENT_KEY_MANAGER=memory`.
- Redemption's authoritative binding is the clone UUID. `[INFERENCE]` The host agent derives
  `incus:uuid:719d84e1-…` for the clone, which does not match the only exchange entry's
  `incus:uuid:a955ca30-…` selector, so the broker receives no exchange SVID.
- A's original node stays attested.

**Observed:**

*1 — UUID and generation (matches P6 §2 exactly).*

| Field | `spike-guest-a` | `spike-p10-c6-clone` |
|---|---|---|
| `volatile.uuid` | `a955ca30-a0dc-4087-a369-37d53d389c5a` | `719d84e1-673e-40dc-a4f7-24d322ee9971` |
| `volatile.uuid.generation` | `c32efc7b-f3d8-4637-9818-f8906c35543a` | `719d84e1-673e-40dc-a4f7-24d322ee9971` |
| `project` | `spike-spiffe` | `spike-spiffe` |
| `type` | `virtual-machine` | `virtual-machine` |
| `volatile.base_image` | `9eb18b1a9368…acee7` | `9eb18b1a9368…acee7` (preserved) |
| `created_at` | `2026-08-17T03:18:09.069463101Z` | `2026-08-17T18:19:43.610173436Z` |

The clone's generation equals its own new UUID, exactly the "equal to `volatile.uuid` at creation
and after every copy" behaviour P6 froze, and both values still equalled those after the clone's
first boot. `[DERIVED]` The clone-shaped selector outcome from these host-side fields is that
`incus:uuid`, `incus:generation`, and `incus:name` change while `incus:project`, `incus:type`, and
`incus:image` do not. No host-agent selector transcript exists for this redemption.

*2 — Guest API reports the clone.* The `/dev/incus/sock` `GET /1.0` body on this Incus 7.3 carries
only `api_version`, `instance_type`, `location` and `state` — no name and no UUID — so self-identity
was read from `GET /1.0/meta-data` and from DMI:

```
spike-guest-a       local-hostname: spike-guest-a        DMI product_uuid a955ca30-a0dc-4087-a369-37d53d389c5a
spike-p10-c6-clone  local-hostname: spike-p10-c6-clone   DMI product_uuid 719d84e1-673e-40dc-a4f7-24d322ee9971
```

The clone's socket answered `HTTP 404` for `GET /1.0/config/user.spiffe-bootstrap` before its own
nonce existed. A first transcript line claimed `meta-data instance-id` equalled the clone UUID; that
was wrong (`instance-id` is `volatile.cloud-init.instance-id`) and the transcript carries a visible
correction rather than a silent edit. Per P6 §2 the DMI value is a *claim* rendered from
`volatile.uuid` at boot, not corroboration; the anchor remains the host-side Incus record.

*3 — What the copied disk actually carried.* Precisely this, and nothing else:

| Present on the clone | Assessment |
|---|---|
| `/var/lib/spire-agent/agent-data.json` (3358 bytes, mode 0600) — keys `bootstrap_start_time`, `bootstrap_use`, `bundle`, `connection_attempts`, `reattestable`, `svid` | A's node **certificate** and cached bundle. Certificates only; `AGENT_KEY_MANAGER=memory` means the node private key was never written to disk, so this is public material and inert |
| `/var/lib/spire-agent/bundle.pem`, sha256 `5a7793f3dee418d2fb5d895645141682010fef49a53c5127bfc50f900281bd35` — identical to A's | The trust bundle: public material by Appendix D rule 3 |
| `/root/p9/` harness (`agent.conf.template`, `broker-ca.pem`, `guest-agent-bootstrap.sh`, `guest-workload-check.sh`) | Spike tooling and a public CA cert |
| `/run/spike-exchange` | **Absent** — the tmpfs did not survive |
| `svid.key`, `svid.pem`, `agent_svid.der`, `redeem-response*` anywhere under `/` | **Zero matches** |
| Files containing a `PRIVATE KEY` block: 5 | Attributed in full: `freedesktop.org.xml` and an APT `Translation-en` list (the literal string in text), the two harness scripts (the string in comments), and `/run/incus_agent/agent.key` (288 bytes) — the Incus guest agent's own per-boot TLS key, not SPIRE material |

*Can that copied state start?* No. Rendering the harness's own template and running the agent gave
a valid config and then, verbatim:

```
level=error msg="Failed to configure plugin" error="rpc error: code = InvalidArgument desc = unable to load keypair: open /run/spike-exchange/svid.pem: no such file or directory" external=false plugin_name=x509pop plugin_type=NodeAttestor subsystem_name=catalog
level=error msg="Agent crashed" error="failed to configure plugin \"x509pop\": rpc error: code = InvalidArgument desc = unable to load keypair: open /run/spike-exchange/svid.pem: no such file or directory"
```

It failed at plugin configuration and never spoke to the server. This is the same message P9 A17
recorded for `EXCHANGE_RETENTION=shred`, now reproduced as a clone property: **the copied node
certificate is unusable because the key that proves possession of it does not exist on the disk, and
the exchange credential that could mint a new one is gone.**

*4 — Clone-bound redemption, no claimed identity.* Mint for the clone UUID returned `HTTP 201`,
`nonce_id=57029e26861b50c1ad8f94d275e31f92`, `instance_name=spike-p10-c6-clone`,
`generation_uuid=719d84e1-…`. The clone's `user.spiffe-bootstrap` then held 267 bytes with field
names `broker_fingerprint, broker_url, nonce, nonce_id`. Redemption from the clone:

```
redeem: POST https://10.55.156.44:8443/v1alpha1/redeem nonce_id=57029e26861b50c1ad8f94d275e31f92
redeem: HTTP 503
RESULT phase=p9-bootstrap outcome=ERROR reason=redeem_rejected status=503 nonce_id=57029e26861b50c1ad8f94d275e31f92 broker_reason=nonce_consumed_without_svid
```

harness exit `13`. The broker journal names the binding it resolved **itself**:

```
{"level":"INFO","msg":"bootstrap key cleared","operation":"redeem","nonce_id":"57029e26861b50c1ad8f94d275e31f92","instance_uuid":"719d84e1-673e-40dc-a4f7-24d322ee9971","instance_name":"spike-p10-c6-clone","project":"spike-spiffe"}
{"level":"ERROR","msg":"nonce consumed but no exchange SVID was issued","operation":"redeem","outcome":"burned","nonce_id":"57029e26861b50c1ad8f94d275e31f92","instance_uuid":"719d84e1-673e-40dc-a4f7-24d322ee9971","project":"spike-spiffe","failure_class":"broker_no_svid","peer_address":"10.55.156.165:46940","http_status":503,"code":"nonce_consumed_without_svid","reason":"broker delivered no X.509-SVID: response carried an empty SVID list"}
```

Failure class: `broker_no_svid`, outcome `burned` — the documented P9 F3 contract. The bound UUID is
the clone's. The clone's bootstrap key was cleared to 1 byte on consume, so the value is spent.

*5 — No A exchange SVID was returned to the broker, and no A node identity was observed or changed.*

- `exchange_spiffe_id` occurrences in the broker journal for the redeem window: **0**.
- Occurrences of `a955ca30-a0dc-4087-a369-37d53d389c5a` in the broker journal for that window: **0**.
- Nodes whose SPIFFE ID contains the clone UUID: **0**. `agent list` still found exactly two agents.
- `entry show` still found exactly two entries — the broker entry and A's exchange entry, unchanged.
- A's `x509pop` node serial was `142664646892380702363741184904059716611` before the case and
  `142664646892380702363741184904059716611` after it: the same certificate, never reissued and never
  evicted. A's in-guest agent was still running (`spire-agent run -config /run/spike-p9/agent.conf`).
- A's `volatile.uuid` and `volatile.uuid.generation` were unchanged by the snapshot and the copy.

*Limitation, stated rather than papered over.* The `spire-agent` container is an OCI image with no
shell and no journal, and `incus info --show-log` returns the LXC supervisor log rather than the
agent's stdout, so there is no host-agent selector transcript on this deployment. The broker journal
directly establishes the resolved clone UUID and the redemption result, but not the host agent's
selector derivation. `[INFERENCE]` The selector-mismatch cause is that the host agent derived
`incus:uuid:719d84e1-…` for the clone while the only exchange entry selects
`incus:uuid:a955ca30-…`. The direct observations are the clone UUID and generation, the `503` burn
bound to the clone UUID, the empty SVID result, A's unchanged node serial, and the absence of a clone
node.

**Cleanup:** `incus delete ovh-incusos:spike-p10-c6-clone --project spike-spiffe --force` (exit 0)
and `incus snapshot delete ovh-incusos:spike-guest-a p10-c6-src --project spike-spiffe` (exit 0).
Post-cleanup: project `spike-spiffe` holds `spike-authz-probe`, `spike-guest-a` and `spike-guest-b`,
all `RUNNING`; `snapshot list` on A is empty; the two registration entries and the two attested
nodes are unchanged. The clone's nonce was burned on use, so no live credential outlived the case.

## Secret handling

No nonce value, private key, or bearer token appears in this file or its transcript. Nonce secrets
moved only over stdin into mode-0600 files and were shredded; only nonce IDs, expiry times,
certificate serials, validity windows, payload digests, selectors and HTTP codes are recorded. The
executed Appendix D scan — nine canonical patterns, a planted positive control that fired on all
nine, three disclosed scan defects, and zero hits on the real evidence — is in
[`wave-02-final-state.txt`](./wave-02-final-state.txt) §§ 1–9.

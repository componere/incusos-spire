# P9 guest `x509pop` bootstrap, guest-local SPIRE Agent, guest Workload API

**This directory is disposable spike tooling.** Appendix C of `SPIKE_PLAN.md`
classifies everything under `spike/` as never merged as product code: throwaway
configs and operator scripts, deletable without loss, because the evidence they
produce lives in the journal. Nothing here is imported, wrapped, or promoted. The
durable counterparts are `cmd/incus-spiffe-broker`, `internal/broker`,
`internal/nonce`, `internal/incus/bootstrap`, `internal/incus/identity`,
`internal/attestor` and `cmd/incus-attestor`.

| File | Runs where | Purpose |
| --- | --- | --- |
| `guest-agent-bootstrap.sh` | as root **inside** a guest | redeem the nonce for an exchange SVID, start a guest-local `spire-agent` on `x509pop`, report the node SPIFFE ID, destroy the exchange material |
| `agent.conf.template` | rendered inside the guest | the guest SPIRE Agent 1.15.2 configuration, with `@@<NAME>@@` placeholders the script substitutes |
| `guest-workload-check.sh` | as root **inside** a guest | fetch an SVID from the guest's own Workload API, assert its SPIFFE ID, and prove it rotates |

## ⚠ The redeem response now carries a private key

P8's redeem answer was binding metadata. **P9's redeem answer is a credential.**
The body contains the exchange SVID's certificate chain, its **private key**, and
the trust bundle. Consequences that are not negotiable:

- **No transcript may capture a redeem response body verbatim.** Not `curl -v`,
  not `curl -i`, not a proxy log, not a paste into the journal. Appendix D rule 1
  puts private keys in the same class as nonce values and recovery keys.
- `guest-agent-bootstrap.sh` never prints the body, never assigns the key to a
  shell variable, and never lets it leave the tmpfs described below. The key moves
  from `jq`'s stdout straight into a mode-0600 file.
- Foreign output that the harness relays — `curl` and `openssl` stderr, the agent
  log, the `spire-agent` CLI's own stdout — passes through a filter that withholds
  any line containing a PEM private-key header or a long line that is nothing but
  base64. A future SPIRE CLI that starts printing material cannot leak through
  this harness.
- The nonce keeps every P8 protection: it never reaches `argv` (world-readable
  through `/proc`), the request body is built by `jq` from `jq`'s own stdin and
  piped to `curl` on stdin, `grep` patterns come from a file, and a response that
  echoes the secret is withheld entirely and reported as a contract violation.

Both scripts print only what Appendix D rule 3 permits: SPIFFE IDs, certificate
serials, validity windows, fingerprints, payload digests, selectors, UUIDs,
generations, counts and HTTP status codes.

## What the chain proves, and where the trust actually comes from

Nothing the guest does establishes its identity. The exchange SVID exists only
because the physically attested **host** agent's `incus-attestor` plugin
independently derived `incus:uuid:<uuid>` from the authoritative Incus instance
record, and the SPIRE server matched a registration entry keyed on that selector.
The guest merely proves possession of a single-use nonce that the broker wrote
into its instance configuration. The trust root is the host TPM.

```
mint (operator)          spike/p8/operator-mint.sh
   │  nonce, hash stored, user.spiffe-bootstrap written
   ▼
redeem (guest)           guest-agent-bootstrap.sh
   │  broker resolves the binding server-side, then asks the host agent's
   │  Broker API for an SVID via IncusInstanceReference{instance_uuid}
   │  → the host attestor re-derives incus:uuid:<uuid> from live Incus state
   ▼
exchange SVID            spiffe://spike.incus.internal/spire-exchange/incus/<uuid>
   │  written to tmpfs, used once by NodeAttestor "x509pop"
   ▼
node SVID                spiffe://spike.incus.internal/spire/agent/x509pop/incus/<uuid>
   │  server x509pop mode="spiffe" verifies the chain against its own bundle and
   │  the proof of possession, then applies svid_prefix="/spire-exchange" and
   │  agent_path_template="{{ .PluginName }}/{{ .SVIDPathTrimmed }}" (v1.15.2 defaults)
   ▼
guest Workload API       /tmp/spire-agent/public/api.sock — an ordinary SPIFFE
                         Workload API, verified by guest-workload-check.sh
```

Both prefixes are variables (`EXCHANGE_ID_PREFIX`, `NODE_ID_PREFIX`), because
P9's own acceptance is that the documented v1.15.2 defaults produce these forms;
`SPIKE_PLAN.md` classifies a prefix or template mismatch as configuration, not
architecture.

## The tmpfs and shred policy, and why it is not a solution

`SPIKE_PLAN.md` P9 step 2 requires this spike to **record** how the exchange key
is delivered and held rather than declare the problem solved. Risk R7 is an
explicit pre-production hardening item in the go/no-go. The implemented stance:

| Property | How |
| --- | --- |
| memory-only | `guest-agent-bootstrap.sh` mounts its own tmpfs (`mount -t tmpfs -o size=1m,mode=0700,nosuid,nodev,noexec`) at `EXCHANGE_DIR` and refuses to run if it cannot — it asserts `stat -f -c %T` is `tmpfs` before requesting anything. The nonce is not sent when that check fails (exit `7`) |
| everything, not just the key | the bootstrap payload, the redeem **response body**, the certificate, the key and the bundle all live only in that tmpfs, mode 0600 in a mode-0700 directory. The response file is shredded as soon as the three PEM blobs have been extracted |
| single-use | the material is used for exactly one `x509pop` attestation |
| short-lived | it is shredded and the tmpfs unmounted the moment attestation succeeds, and the script **verifies** both — a failure to reclaim exits `8`, which supersedes even a successful attestation, because a live key that outlived its use is the most urgent fact of the run |
| on abort too | an `EXIT` trap reclaims on every path. `KEEP_EXCHANGE_MATERIAL=1` defers the shred **only on a failed run**, prints the exact reclaim command, and never applies to a successful one |

What this does **not** prove, stated plainly because Appendix D rule 2 forbids
claiming erasure that has not been demonstrated: tmpfs pages can be swapped; a
memory dump or a hypervisor-side read of guest RAM sees the key while it is live;
and `shred(1)` on tmpfs is an overwrite of pages plus an unlink, **not**
cryptographic erasure. The honest claim is scope reduction — memory-only,
single-use, short-lived — and that the key never touches a persistent guest
filesystem, so it cannot be recovered from a disk image, a volume or a snapshot.

The nonce is still a bearer credential between mint and redemption (P8 case i).
P9 does not change that; it shortens the window in which the *exchange* credential
is one.

## The re-attestation story (P9 step 4), decided rather than discovered

`AGENT_KEY_MANAGER=memory` is the default and the recorded choice:

- the agent's own node-SVID key stays in memory, so an agent restart or a guest
  reboot loses it and the agent must re-attest;
- it cannot, because the exchange credential was shredded after its single use,
  and `PERSIST_TRUST_BUNDLE=0` would additionally leave `trust_bundle_path`
  pointing at a file that no longer exists, so the agent would not even start;
- therefore the intended recovery is explicit: **one bootstrap per boot.** The
  operator mints a fresh nonce and re-runs `guest-agent-bootstrap.sh`. A stale
  nonce is refused with `409` (exit `11`), which is the same fail-closed answer
  P10 cases 3, 6, 7 and 10 expect from a cloned, restored or rolled-back guest.

`AGENT_KEY_MANAGER=disk` renders the other half of the tradeoff and is worth
measuring once: the node key persists in `data_dir`, the agent resumes its node
identity across a restart without re-attesting, and a new exchange credential is
needed only after the node SVID expires. The cost is a long-lived identity key on
the guest filesystem — carried away by any snapshot, disk image or stolen volume —
and a node identity that is no longer tied to a live Incus instance record, which
is the property the whole architecture rests on. The tradeoff is recorded beside
the `KeyManager` block in `agent.conf.template`, as the plan asks.

`PERSIST_TRUST_BUNDLE=1` (default) copies only the **trust bundle** to
`$AGENT_DATA_DIR/bundle.pem`. That is public material under Appendix D rule 3, and
it is what lets the agent be restarted for a P10 case without a full re-bootstrap.
The private key is never persisted under either setting.

## Running the three pieces, in order

```sh
# 0. mint a nonce for the guest (P8 harness, operator side)
cd ../p8
BROKER_URL=https://10.55.156.44:8443 BROKER_CACERT=/etc/spike/broker-ca.pem \
MINT_AUTH_TOKEN_FILE=/etc/spike/mint-token \
./operator-mint.sh a955ca30-a0dc-4087-a369-37d53d389c5a spike-spiffe

# 1. stage the P9 harness into the guest and bootstrap it
cd ../p9
incus file push guest-agent-bootstrap.sh spike-guest-a/root/p9/ --create-dirs --mode 0700
incus file push agent.conf.template     spike-guest-a/root/p9/ --mode 0600
incus file push guest-workload-check.sh spike-guest-a/root/p9/ --mode 0700
incus file push /etc/spike/broker-ca.pem spike-guest-a/root/p9/ --mode 0600

incus exec spike-guest-a -- env \
  SPIRE_SERVER_ADDRESS=10.55.156.10 SPIRE_SERVER_PORT=8081 \
  TRUST_DOMAIN=spike.incus.internal \
  BROKER_CACERT=/root/p9/broker-ca.pem \
  /root/p9/guest-agent-bootstrap.sh

# 2. register a guest workload entry on the server (unix selectors), then check it
incus exec spike-guest-a -- /root/p9/guest-workload-check.sh \
  spiffe://spike.incus.internal/guest/demo
```

Each script is self-contained: they are pushed and run individually, so the tmpfs
and shred logic is duplicated between them rather than shared through a library
that would have to be pushed too.

### In-guest dependencies

`curl`, `jq`, `openssl`, `spire-agent`, `mount`, `umount`, `shred`, `base64`,
`find`, `stat`, `date`, `setsid` (background mode), plus `systemd-run`,
`systemctl` and `journalctl` for `AGENT_START_MODE=systemd` and `timeout` for
`ROTATION_MODE=watch`. A missing binary exits `6` and says which one — the P8 live
run lost a case to a guest with no `jq` and only saw `exit 2`. Stock
`images:debian/13` has no `jq`.

## `guest-agent-bootstrap.sh`

Steps, in order, each one printed:

1. **preflight** — dependencies, guest root, mode validation, and
   `SPIRE_SERVER_ADDRESS`;
2. **tmpfs first** — before the nonce is read and before anything is transmitted;
3. **guest read** — `GET /1.0/config/user.spiffe-bootstrap` over
   `/dev/incus/sock`, the raw configured string with no JSON envelope, guest root
   only (source-pinned in `evidence/p8/GUEST_SOCK_BRIEF.md`);
4. **pin, then transmit** — the broker leaf is fetched with `openssl s_client` and
   its SHA-256 compared with the payload's `broker_fingerprint`; a mismatch aborts
   with exit `5` **before the nonce is sent**. The SPKI hash of that same
   certificate is then handed to `curl --pinnedpubkey`, so the request must reach
   the certificate that was just verified, and `--cacert "$BROKER_CACERT"` adds an
   ordinary chain validation on top;
5. **redeem** — `POST /v1alpha1/redeem` with `{nonce_id, nonce}`;
6. **unpack** — the three PEM blobs into the tmpfs, then four checks that cost
   nothing and turn a silent attestation failure into a precise one: the key
   parses, the key's public part matches the certificate's (`x509pop` will have to
   sign a challenge with it), the certificate carries a `spiffe://` URI SAN, and
   that SAN is the expected exchange ID (exit `23` otherwise, and the agent is not
   started);
7. **render** — `agent.conf.template` through `sed`, then
   `spire-agent validate -config` on the result, so a bad substitution fails here
   instead of at attestation;
8. **start** — `background` (default, `setsid` so the agent survives
   `incus exec` returning), `systemd` (a transient `systemd-run --collect` unit,
   no unit file left behind), or `none` (render and deliver only);
9. **wait** — for two independent signals: the node SVID, read out of
   `$AGENT_DATA_DIR/agent-data.json` where SPIRE 1.15.2 stores it as base64-wrapped
   PEM under `.svid` (certificates only, no key), with the agent log line `Node
   attestation was successful` as a fallback; and `spire-agent healthcheck`
   passing on the Workload API socket. An attested agent with a dead socket proves
   half the phase, so both are required;
10. **check** — the node SPIFFE ID against
    `spiffe://$TRUST_DOMAIN$NODE_ID_PREFIX/<instance-uuid>`;
11. **reclaim** — shred, unmount, verify, and report the observed outcome on the
    `RESULT` line rather than an intention.

### Environment contract

| Variable | Default | Purpose |
| --- | --- | --- |
| `SPIRE_SERVER_ADDRESS` | **required** | SPIRE server the guest agent dials. No default on purpose: a wrong guess would surface as an attestation timeout instead of a configuration error |
| `SPIRE_SERVER_PORT` | `8081` | SPIRE server port |
| `TRUST_DOMAIN` | `spike.incus.internal` | trust domain, and the base of both expected SPIFFE IDs |
| `EXCHANGE_ID_PREFIX` | `/spire-exchange/incus` | expected exchange SVID path prefix |
| `NODE_ID_PREFIX` | `/spire/agent/x509pop/incus` | expected node SVID path prefix (the v1.15.2 `svid_prefix` + `agent_path_template` result) |
| `ALLOW_UNEXPECTED_EXCHANGE_ID` | `0` | `1` starts the agent anyway when the delivered exchange ID is not the expected form, to observe what node path it produces |
| `GUEST_SOCKET` | `/dev/incus/sock` | guest API socket |
| `BOOTSTRAP_KEY` | `user.spiffe-bootstrap` | configuration key to read |
| `PAYLOAD_FILE` | unset | read the bootstrap payload from a file instead of the socket (P10 staging) |
| `BROKER_URL_OVERRIDE` | unset | override the payload's `broker_url` (split-horizon DNS only) |
| `REDEEM_PATH` | `/v1alpha1/redeem` | redeem endpoint path |
| `BROKER_CACERT` | unset | spike CA for chain validation inside the guest; strongly recommended |
| `BROKER_TLS_HOSTNAME` | unset | certificate SAN to validate against, via `--connect-to` |
| `ALLOW_INSECURE_TLS` | `0` | explicit opt-in that disables only curl's chain and hostname validation; the fingerprint comparison and SPKI pin still run, and a warning tells you to record it. This request carries a nonce out and brings a private key back — prefer `BROKER_CACERT` |
| `CONNECT_TIMEOUT` / `MAX_TIME` | `5` / `30` | curl timeouts, seconds. `MAX_TIME` is longer than P8's because the broker now makes a Broker API round trip |
| `EXCHANGE_DIR` | `/run/spike-exchange` | the tmpfs this script mounts and later unmounts |
| `EXCHANGE_TMPFS_SIZE` | `1m` | tmpfs size |
| `KEEP_EXCHANGE_MATERIAL` | `0` | `1` keeps the tmpfs **on a failed run only**, for debugging; prints the reclaim command |
| `PERSIST_TRUST_BUNDLE` | `1` | copy the public trust bundle to `$AGENT_DATA_DIR/bundle.pem` so the agent can be restarted; `0` keeps everything memory-only and the agent cannot start again after the shred |
| `AGENT_CONF_TEMPLATE` | `agent.conf.template` beside the script | template to render |
| `AGENT_RUN_DIR` | `/run/spike-p9` | 0700 directory for the rendered config, the pidfile and the agent log |
| `AGENT_DATA_DIR` | `/var/lib/spire-agent` | agent `data_dir`; P9's rollback note allows guest agent state on guest disk |
| `AGENT_SOCKET_PATH` | `/tmp/spire-agent/public/api.sock` | in-guest Workload API socket (the SPIRE default) |
| `AGENT_KEY_MANAGER` | `memory` | `memory` or `disk`; see the re-attestation story above |
| `AGENT_LOG_LEVEL` | `DEBUG` | agent log level |
| `AGENT_HEALTH_BIND_ADDRESS` / `AGENT_HEALTH_BIND_PORT` | `localhost` / `8080` | health-check listener |
| `AGENT_START_MODE` | `background` | `background`, `systemd`, or `none` |
| `AGENT_UNIT` | `spike-spire-agent` | transient unit name for `systemd` mode |
| `AGENT_READY_TIMEOUT` | `90` | seconds to wait for attestation **and** a ready Workload API |
| `CHAIN_JQ` / `KEY_JQ` / `BUNDLE_JQ` | unset | explicit `jq` filters for the three PEM fields, when the broker's field names differ from every spelling below |
| `CURL_BIN` `JQ_BIN` `OPENSSL_BIN` `SPIRE_AGENT_BIN` | `curl` `jq` `openssl` `spire-agent` | binaries |

### Redeem response shape it accepts

The three PEM fields are looked up at the top level and inside `.exchange_svid`,
`.svid` and `.exchange`, under any of these spellings, because a spike broker's
field naming is not a frozen contract and a live run must not die over cosmetics:

| Material | Accepted names |
| --- | --- |
| certificate chain, leaf first | `svid_chain_pem`, `certificate_chain_pem`, `svid_pem`, `certificate_pem`, `chain_pem`, `x509_svid_pem`, `cert_chain_pem` |
| private key | `svid_key_pem`, `private_key_pem`, `key_pem`, `x509_svid_key_pem`, `svid_private_key_pem` |
| trust bundle | `trust_bundle_pem`, `bundle_pem`, `trust_bundle`, `svid_bundle_pem`, `x509_bundle_pem` |

So both of these work, and anything else is reachable with `CHAIN_JQ`, `KEY_JQ`
and `BUNDLE_JQ`:

```json
{"exchange_svid": {"spiffe_id": "…", "svid_chain_pem": "…", "svid_key_pem": "…"},
 "trust_bundle_pem": "…"}

{"certificate_chain_pem": "…", "private_key_pem": "…", "bundle_pem": "…"}
```

The binding metadata is read with P8's spellings (`instance_uuid`/`uuid`,
`instance_name`/`name`, `generation`/`generation_uuid`, `project`) and printed;
`selectors` is printed as a comma-joined list. Missing material is reported as
`reason=exchange_material_missing missing=private_key` — the field names the
harness looked for, never the body, which may contain a key. The exchange SVID's
own SPIFFE ID, serial and validity window are read from the **certificate**, not
from a JSON field, so they cannot disagree with what the agent will present.

### Exit codes

| Exit | Meaning |
| --- | --- |
| `0` | **PASS**: attested, node SPIFFE ID as expected, exchange material shredded and unmounted |
| `2` | usage: an unexpected argument, a missing `SPIRE_SERVER_ADDRESS`, a bad `AGENT_START_MODE`/`AGENT_KEY_MANAGER`, an unreadable file, an unrenderable template |
| `3` | guest socket read failed: key absent (404), forbidden (403), or the socket is unreachable |
| `4` | malformed payload, or malformed/missing exchange material: not PEM, an unparseable key, a key that does not match the certificate, or a certificate with no `spiffe://` URI SAN |
| `5` | **fingerprint mismatch — the nonce was NOT sent** |
| `6` | a required binary is missing inside the guest (`reason=missing_dependency dependency=<name>`) |
| `7` | no memory-backed directory could be established. Nothing was requested and the nonce was NOT sent: this script refuses to put an exchange key on a persistent guest filesystem |
| `8` | **the exchange material could not be shredded and unmounted.** It supersedes every other code, including `0` |
| `10` | redeem `401` — unknown nonce ID or wrong secret (one status for both, so IDs cannot be enumerated) |
| `11` | redeem `409` — the nonce exists and the secret matched, but its state forbids redemption: consumed, expired, wrong instance, or the generation moved. **This is the expected answer for a stale nonce after a reboot** |
| `12` | redeem `500` — broker internal fault |
| `13` | redeem `503` — a broker dependency is unavailable: the nonce store, the Incus API, or the host agent's Broker API endpoint that mints the exchange SVID. Retryable |
| `14` | another non-2xx status, or a response that echoed the nonce secret |
| `15` | redeem transport failure: no HTTP status was obtained |
| `20` | **ERROR** — the agent did not attest, or its Workload API never became ready, within `AGENT_READY_TIMEOUT`. No decision was observed |
| `21` | **FAIL** — the agent attested but the node SPIFFE ID is not the expected form (an `svid_prefix`/`agent_path_template` mismatch is configuration, not architecture) |
| `23` | **FAIL** — the delivered exchange SVID's SPIFFE ID is not the expected form; the agent is not started, because the node path derived from it would be wrong |

`AGENT_START_MODE=none` ends with `outcome=STAGED` and exit `0`, leaves the
material live in the tmpfs on purpose, and prints the reclaim command.

## `agent.conf.template`

A SPIRE Agent 1.15.2 configuration with `@@<NAME>@@` placeholders. Every field a
guest `x509pop` agent needs is present: `trust_domain`, `server_address`,
`server_port`, `trust_bundle_path`, `data_dir`, `socket_path`, `log_level`,
`NodeAttestor "x509pop"` with `certificate_path` and `private_key_path`, a
`KeyManager`, `WorkloadAttestor "unix"`, and a `health_checks` listener.

- `certificate_path` takes the leaf **followed by any intermediates in one file**,
  which is exactly how the broker delivers the chain, so `intermediates_path` is
  not needed. The plugin's `spiffe_endpoint_socket` alternative is irrelevant
  here: the guest has no Workload API until this attestation succeeds.
- The `KeyManager` block carries the restart tradeoff as a comment, because P9
  step 4 asks for the re-attestation story to be defined rather than discovered.
- `WorkloadAttestor "unix"` is the only workload attestor: nothing
  Incus-specific runs inside the guest. The Incus-derived selectors belong to the
  host agent's `incus-attestor` plugin, one trust boundary further out.
- Placeholder names are listed in the template header **without** their `@@`
  markers so the header stays readable after rendering; the renderer refuses any
  value containing `|` (its `sed` delimiter) and fails if any `@@NAME@@` survives.

## `guest-workload-check.sh`

Fetches with `spire-agent api fetch x509 -write` into a self-mounted tmpfs, reads
the certificate, and shreds the key the CLI wrote as soon as the certificate has
been parsed. The fetch itself verifies the SVID against the trust bundle before
printing anything, so a successful fetch is a chain check too.

Three outcomes, the P8 convention unchanged:

| Outcome | Meaning |
| --- | --- |
| **PASS** | the behavior under test was observed and was correct |
| **FAIL** | it was observed and was wrong: a different SPIFFE ID, or no rotation after the renewal point had passed |
| **ERROR** | nothing was observed: a missing dependency, an unreachable Workload API, or a rotation window longer than this run may wait |

Rotation is derived from the certificate, not assumed: SPIRE rotates an X509-SVID
at half its lifetime, so the target is
`notBefore + lifetime/2 + ROTATION_GRACE_SECONDS`, floored at
`now + ROTATION_MIN_WAIT_SECONDS` so an already-passed renewal point is still
given real observation time instead of being judged by one extra fetch. If the
resulting wait exceeds `ROTATION_MAX_WAIT_SECONDS` the case is an **ERROR** that
tells you to shorten the registration entry's `x509SVIDTTL`, not a silent
multi-hour hang.

| Variable | Default | Purpose |
| --- | --- | --- |
| `EXPECTED_SPIFFE_ID` | **required** (or the first positional argument) | the SPIFFE ID the workload must receive. Without it the script can report an SVID but cannot decide anything |
| `SOCKET_PATH` | `/tmp/spire-agent/public/api.sock` | the guest's own Workload API socket |
| `SPIRE_AGENT_BIN` | `spire-agent` | CLI used as the workload client |
| `FETCH_TIMEOUT` | `10s` | passed to `api fetch -timeout` |
| `ROTATION_MODE` | `poll` | `poll` compares certificate serials around the renewal point; `watch` runs `api watch` under `timeout(1)` and counts updates (no serials — `api watch` has no timeout flag and prints none); `skip` asserts issuance only and says the run is **not** complete evidence |
| `ROTATION_MAX_WAIT_SECONDS` | `900` | hard cap on the wait; exceeding it is ERROR `22` |
| `ROTATION_MIN_WAIT_SECONDS` | `45` | minimum polling past the renewal point before a FAIL |
| `ROTATION_POLL_INTERVAL` | `15` | seconds between fetches |
| `ROTATION_GRACE_SECONDS` | `30` | slack after the computed renewal point |
| `WORK_MOUNT` | `/run/spike-workload-check` | tmpfs for the fetched material |
| `WORK_TMPFS_SIZE` | `1m` | tmpfs size |
| `ALLOW_NON_TMPFS_WORKDIR` | `0` | `1` permits a disk-backed work directory; the fetch writes a private key, so this is an explicit choice to record |
| `OPENSSL_BIN` | `openssl` | certificate parsing |

| Exit | Meaning |
| --- | --- |
| `0` | **PASS**: the expected SPIFFE ID was issued and a rotation was observed |
| `2` | usage: no expected SPIFFE ID, one that is not a `spiffe://` URI, an unexpected argument, a bad `ROTATION_MODE` |
| `6` | a required binary is missing inside the guest |
| `7` | no memory-backed work directory could be established |
| `8` | the fetched material could not be shredded and unmounted; supersedes every other code |
| `10` | **ERROR** — the Workload API returned nothing usable, or stopped answering mid-wait |
| `20` | **FAIL** — the SVID's SPIFFE ID is not the expected value (also checked again after rotation: a rotation must not change who the workload is) |
| `21` | **FAIL** — the serial did not change after the renewal point plus grace and the minimum observation window: the agent is not rotating |
| `22` | **ERROR** — the rotation window exceeds `ROTATION_MAX_WAIT_SECONDS`, or the validity window could not be parsed |

`RESULT` lines are machine-parseable and there are three of them:

```
RESULT check=issuance outcome=PASS spiffe_id=… serial=… not_before=… not_after=…
RESULT check=rotation outcome=PASS mode=poll first_serial=… second_serial=… waited_seconds=… spiffe_id=…
RESULT check=workload outcome=PASS spiffe_id=… socket=… first_serial=… second_serial=… rotation=observed mode=poll material=shredded-and-unmounted
```

and the bootstrap emits one:

```
RESULT phase=p9-bootstrap outcome=PASS nonce_id=… instance_uuid=… \
  exchange_spiffe_id=spiffe://spike.incus.internal/spire-exchange/incus/<uuid> \
  exchange_not_after=… node_spiffe_id=spiffe://spike.incus.internal/spire/agent/x509pop/incus/<uuid> \
  key_manager=memory workload_api=/tmp/spire-agent/public/api.sock \
  exchange_material=shredded-and-unmounted
```

## What each step proves

| Step | Proves | Expected |
| --- | --- | --- |
| guest read | delivery is per-instance: only this guest's own `/dev/incus/sock` exposes its bootstrap value | HTTP `200`, payload with four fields |
| pin before transmit | the guest will not hand its nonce to an unverified endpoint | fingerprints equal; a mismatch is exit `5` with no request sent |
| redeem | the broker resolves the binding server-side and returns a credential for the identity the **host** attested | HTTP `200`, exchange SVID for the bound UUID |
| exchange ID check | the broker asked the Broker API for the right reference and the server matched the `incus:uuid:<uuid>` entry | `spiffe://<td>/spire-exchange/incus/<uuid>` |
| key/certificate check | proof of possession will work; a wrong pairing fails here, not silently at attestation | public-key digests equal |
| attestation | server `x509pop` `mode="spiffe"` accepted the chain against its own bundle and the challenge signature, and the v1.15.2 defaults produced the documented path | `spiffe://<td>/spire/agent/x509pop/incus/<uuid>` |
| healthcheck | the phase's actual deliverable, a serving Workload API, not just an attested agent | `healthcheck` passes on the socket |
| reclaim | the exchange key does not outlive its single use | `exchange_material=shredded-and-unmounted`, `EXCHANGE_DIR` unmounted and empty |
| issuance | an in-guest app gets its SVID from an ordinary local Workload API with no spike-specific client | the expected workload SPIFFE ID |
| rotation | the agent holds a live relationship with the server rather than a one-shot credential — the basis for the P10 stale-credential cases | the serial changes, the SPIFFE ID does not |

## Harness self-check

The logic in these scripts was exercised end to end against fakes before the live
run — a fake `/dev/incus/sock`, a fake TLS broker whose certificate is pinned by
fingerprint, and a fake `spire-agent` — in a privileged Debian 13 container, so
the real `mount`/`shred`/`umount`, `mawk`, `jq` and `openssl` behavior was
covered. Verified there: the PASS path end to end (both nested and flat redeem
field names, `memory` and `disk` KeyManagers); a rendered `agent.conf` with no
surviving placeholders that `validate` accepts; the tmpfs unmounted and empty
afterwards on both the success and the abort paths; and the `4`, `5`, `11`, `2`,
`20`, `21`, `22` and `23` failure classes, including that a fingerprint mismatch
sends no request at all and that a wrong exchange ID never starts the agent. No
transcript from any case contained the nonce value or a PEM private key. Those
fakes are not committed: they are scaffolding for scaffolding, and the live run in
`spike-guest-a` is the evidence that counts.

## Before capturing evidence

Appendix D rule 4 asks for a pre-commit check on every evidence file. For a P9
transcript, search it for:

- PEM `PRIVATE KEY` blocks — **there must be none**, and unlike P8 there is now a
  real source for one;
- base64 blobs longer than 64 characters — the harness withholds them, so a hit
  means something outside the harness wrote to the transcript;
- the strings `recovery` and `nonce=` — `nonce=<redacted, present>` is expected, a
  bare value is not.

A clean P9 transcript contains `nonce_id=`, `payload_sha256=`,
`broker_fingerprint=`, `selectors=incus:…`, `exchange_spiffe_id=`,
`node_spiffe_id=`, certificate serials and validity windows, and
`exchange_material=shredded-and-unmounted`. Those are all permitted evidence under
Appendix D rule 3.

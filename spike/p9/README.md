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
| `guest-agent-bootstrap.sh` | as root **inside** a guest | redeem the nonce for an exchange SVID, start a guest-local `spire-agent` on `x509pop`, report the node SPIFFE ID, and reclaim the exchange material |
| `agent.conf.template` | rendered inside the guest | the guest SPIRE Agent 1.15.2 configuration, with `@@<NAME>@@` placeholders the script substitutes |
| `guest-workload-check.sh` | as root **inside** a guest | fetch an SVID from the guest's own Workload API as root **and again as an unprivileged user**, assert the SPIFFE ID, and prove it rotates |

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

## The tmpfs and reclaim policy, and why it is not a solution

`SPIKE_PLAN.md` P9 step 2 requires this spike to **record** how the exchange key
is delivered and held rather than declare the problem solved. Risk R7 is an
explicit pre-production hardening item in the go/no-go. The implemented stance:

| Property | How |
| --- | --- |
| memory-backed | `guest-agent-bootstrap.sh` mounts its own tmpfs (`mount -t tmpfs -o size=1m,mode=0700,nosuid,nodev,noexec`) at `EXCHANGE_DIR` and refuses to run if it cannot — it asserts `stat -f -c %T` is `tmpfs` before requesting anything. The nonce is not sent when that check fails (exit `7`) |
| everything, not just the key | the bootstrap payload, the redeem **response body**, the certificate, the key and the bundle all live only in that tmpfs, mode 0600 in a mode-0700 directory. The response file is overwritten as soon as the three PEM blobs have been extracted |
| single-use | with the default `EXCHANGE_RETENTION=shred` the material is used for exactly one `x509pop` attestation |
| reclaimed, and verified | the files are overwritten with `shred -z` and the tmpfs unmounted the moment attestation succeeds, and the script **verifies** both — the mount is gone and the path is empty. A failure to reclaim exits `8`, which supersedes even a successful attestation |
| on abort too | an `EXIT` trap reclaims on every path. `EXCHANGE_RETENTION=keep-on-failure` defers it **only on a failed run**, prints the exact reclaim command, and never applies to a successful one |
| the nonce never survives | even `EXCHANGE_RETENTION=keep` removes the scratch directory holding the staged payload and the nonce secret. Retention is about the **credential**, never about the nonce (Appendix D rule 1) |

**What is not claimed.** Appendix D rule 2 forbids claiming erasure that has not
been demonstrated, so this harness does not:

- `shred(1)` on tmpfs is an overwrite of pages plus an unlink. It is **not**
  cryptographic erasure, and no wording in these scripts or this document says it
  is;
- tmpfs pages **can be swapped**, so "memory-only" is a description of where the
  file was written, not a guarantee about where its bytes have been;
- a memory dump, or a hypervisor-side read of guest RAM, sees the key while it is
  live.

The claim that *is* made is narrow and observed: the key is never written to a
persistent guest filesystem, it is used once, and at the end of the run the files
are overwritten, the mount is gone and the directory is empty — all three checked
by the script itself, not asserted.

The nonce is still a bearer credential between mint and redemption (P8 case i).
P9 does not change that; it shortens the window in which the *exchange* credential
is one.

## The re-attestation story (P9 step 4), decided rather than discovered

**`x509pop` is re-attestable; this harness deliberately makes this agent not.**
The SPIRE 1.15.2 server returns `CanReattest: true` for `x509pop`
(`evidence/p9/X509POP_BRIEF.md`, pinned to
`pkg/server/plugin/nodeattestor/x509pop/x509pop.go`), and every attestation —
first or later — re-reads the plugin's `certificate_path` and `private_key_path`.
The spike shreds both after the first attestation, so this agent cannot re-attest.
That is a choice, and this is what it looks like live
(`evidence/p9/restart-01-agent-process.txt`):

```
level=error msg="Failed to configure plugin"
  error="rpc error: code = InvalidArgument desc = unable to load keypair:
         open /run/spike-exchange/svid.pem: no such file or directory"
  plugin_name=x509pop plugin_type=NodeAttestor
level=error msg="Agent crashed"
```

**The chosen stance: a fresh credential per boot.** `AGENT_KEY_MANAGER=memory`
plus `EXCHANGE_RETENTION=shred` is the default:

- the agent's own node-SVID key stays in memory, so an agent restart or a guest
  reboot loses it and the agent must re-attest;
- it cannot, because the credential its `x509pop` block names is gone — the crash
  above. `PERSIST_TRUST_BUNDLE=0` would additionally leave `trust_bundle_path`
  pointing at a file that no longer exists, so the agent would not even reach
  that point;
- therefore the intended recovery is explicit: **one bootstrap per boot.** The
  operator mints a fresh nonce and re-runs `guest-agent-bootstrap.sh`. A stale
  nonce is refused with `409` (exit `11`), which is the same fail-closed answer
  P10 cases 3, 6, 7 and 10 expect from a cloned, restored or rolled-back guest.

**The two production alternatives, and what each costs.** Neither is adopted
here; both are recorded because a production system has to pick one.

| Alternative | How | Cost |
| --- | --- | --- |
| Retain the exchange credential for the node's lifetime (`EXCHANGE_RETENTION=keep`) | the certificate and key stay in the tmpfs, so `x509pop` reloads them on every re-attestation and restarts work | contradicts single-use and short-lived directly: a live private key sits in guest memory for the agent's lifetime, anyone who reaches root in the guest can take it and become that node until the credential expires, and tmpfs pages can be swapped. It also does nothing about expiry — past `exchange_expires_at` a fresh nonce is needed anyway |
| `AGENT_KEY_MANAGER=disk` plus a fresh nonce per boot | the node key is written into `data_dir`, so the agent resumes its node identity across a restart without re-attesting; a new exchange credential is needed only when the node SVID finally expires | puts a long-lived identity key on the **guest disk**, where a snapshot, a disk image or a stolen volume carries it away, and decouples the node identity from a live Incus instance record — the property the whole architecture rests on. It defers re-attestation rather than solving it |

`EXCHANGE_RETENTION` is the knob: `shred` (default), `keep-on-failure`
(debugging), or `keep`. Choosing `keep` prints a boxed warning naming the node
identity a stolen key would yield and the expiry that bounds it, and the run's
`RESULT` line records `exchange_retention=keep exchange_material=kept-by-policy`
so no transcript can imply the credential was destroyed when it was not. The same
tradeoff is recorded beside the `KeyManager` block in `agent.conf.template`, as
the plan asks.

`PERSIST_TRUST_BUNDLE=1` (default) copies only the **trust bundle** to
`$AGENT_DATA_DIR/bundle.pem`. That is public material under Appendix D rule 3, and
it is what lets the agent be restarted for a P10 case without a full re-bootstrap.
The private key is never persisted under any setting.

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

# 2. register the guest workload entries on the server, parented to the new guest
#    node. TWO entries, because the phase's claim is about an APPLICATION, not
#    about root: one for uid 0 (the harness itself) and one for the unprivileged
#    uid the non-root check uses. Create the account first so the uid is known:
incus exec spike-guest-a -- useradd --system --no-create-home \
  --shell /usr/sbin/nologin spike-workload
incus exec spike-guest-a -- id -u spike-workload   # e.g. 999

spire-server entry create \
  -parentID spiffe://spike.incus.internal/spire/agent/x509pop/incus/a955ca30-a0dc-4087-a369-37d53d389c5a \
  -spiffeID spiffe://spike.incus.internal/guest/demo -selector unix:uid:0 -x509SVIDTTL 120
spire-server entry create \
  -parentID spiffe://spike.incus.internal/spire/agent/x509pop/incus/a955ca30-a0dc-4087-a369-37d53d389c5a \
  -spiffeID spiffe://spike.incus.internal/guest/demo-app -selector unix:uid:999 -x509SVIDTTL 120

# 3. check issuance and rotation, root and non-root
incus exec spike-guest-a -- env \
  NONROOT_USER=spike-workload \
  NONROOT_EXPECTED_SPIFFE_ID=spiffe://spike.incus.internal/guest/demo-app \
  /root/p9/guest-workload-check.sh spiffe://spike.incus.internal/guest/demo
```

Each script is self-contained: they are pushed and run individually, so the tmpfs
and reclaim logic is duplicated between them rather than shared through a library
that would have to be pushed too.

### In-guest dependencies

`curl`, `jq`, `openssl`, `spire-agent`, `mount`, `umount`, `shred`, `base64`,
`find`, `stat`, `date`, `setsid` (background mode), `runuser` **or** `su` and
`useradd` (the non-root check), plus `systemd-run`, `systemctl` and `journalctl`
for `AGENT_START_MODE=systemd` and `timeout` for `ROTATION_MODE=watch`. A missing
binary exits `6` and says which one — the P8 live run lost a case to a guest with
no `jq` and only saw `exit 2`. Stock `images:debian/13` has no `jq`.

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
6. **unpack** — the three PEM blobs into the tmpfs under the broker's own field
   names, then four checks that cost nothing and turn a silent attestation
   failure into a precise one: the key parses, the key's public part matches the
   certificate's (`x509pop` will have to sign a challenge with it), the
   certificate carries a `spiffe://` URI SAN, and that SAN is the expected
   exchange ID (exit `23` otherwise, and the agent is not started). Every failure
   here happens **after** the broker answered `200`, so each one says
   `nonce_state=consumed` and names the JSON keys involved;
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
    `spiffe://$TRUST_DOMAIN$NODE_ID_PREFIX/<instance-uuid>`, then the observed
    mode of the Workload API socket and its directory, because the non-root claim
    depends on them;
11. **reclaim** — overwrite, unmount, verify, and report the observed outcome on
    the `RESULT` line rather than an intention — unless `EXCHANGE_RETENTION=keep`,
    which reports `exchange_material=kept-by-policy` and says what that costs.

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
| `EXCHANGE_RETENTION` | `shred` | `shred` reclaims the credential as soon as attestation succeeds; `keep-on-failure` keeps the tmpfs **on a failed run only**, for debugging; `keep` retains the credential for the agent's lifetime so `x509pop` can re-attest, and prints what that costs. Every value removes the scratch directory holding the nonce |
| `PERSIST_TRUST_BUNDLE` | `1` | copy the public trust bundle to `$AGENT_DATA_DIR/bundle.pem` so the agent can be restarted; `0` keeps everything in the tmpfs and the agent cannot start again after the reclaim |
| `AGENT_CONF_TEMPLATE` | `agent.conf.template` beside the script | template to render |
| `AGENT_RUN_DIR` | `/run/spike-p9` | 0700 directory for the rendered config, the pidfile and the agent log |
| `AGENT_DATA_DIR` | `/var/lib/spire-agent` | agent `data_dir`; P9's rollback note allows guest agent state on guest disk |
| `AGENT_SOCKET_PATH` | `/tmp/spire-agent/public/api.sock` | in-guest Workload API socket (the SPIRE default). Every directory component is created mode `0755`, not under the script's `umask 077`, so an unprivileged workload can traverse to it; SPIRE serves the socket itself `0777` |
| `AGENT_KEY_MANAGER` | `memory` | `memory` or `disk`; see the re-attestation story above |
| `AGENT_LOG_LEVEL` | `DEBUG` | agent log level |
| `AGENT_HEALTH_BIND_ADDRESS` / `AGENT_HEALTH_BIND_PORT` | `localhost` / `8080` | health-check listener |
| `AGENT_START_MODE` | `background` | `background`, `systemd`, or `none` |
| `AGENT_UNIT` | `spike-spire-agent` | transient unit name for `systemd` mode |
| `AGENT_READY_TIMEOUT` | `90` | seconds to wait for attestation **and** a ready Workload API |
| `CHAIN_JQ` / `KEY_JQ` / `BUNDLE_JQ` | unset | explicit `jq` filters for the three PEM fields, for a broker that is not `cmd/incus-spiffe-broker`. Each is compiled **before** the nonce is sent, so a malformed filter exits `2` without burning a nonce |
| `CURL_BIN` `JQ_BIN` `OPENSSL_BIN` `SPIRE_AGENT_BIN` | `curl` `jq` `openssl` `spire-agent` | binaries |

### Redeem response shape it accepts

**The canonical names are the contract.** They are read from
`cmd/incus-spiffe-broker/service.go` (`type redeemResponse`), which emits:

```json
{"nonce_id": "…", "instance_uuid": "…", "instance_name": "…", "generation": "…",
 "project": "…", "selectors": ["incus:uuid:…"],
 "exchange_spiffe_id": "spiffe://…/spire-exchange/incus/<uuid>",
 "exchange_cert_chain_pem": "-----BEGIN CERTIFICATE-----…",
 "exchange_key_pem": "-----BEGIN PRIVATE KEY-----…",
 "exchange_bundle_pem": "-----BEGIN CERTIFICATE-----…",
 "exchange_expires_at": "2026-08-17T15:38:05Z"}
```

| Material | Canonical name (tried first) | Compatibility spellings (tried after) |
| --- | --- | --- |
| certificate chain, leaf first | `exchange_cert_chain_pem` | `svid_chain_pem`, `certificate_chain_pem`, `svid_pem`, `certificate_pem`, `chain_pem`, `x509_svid_pem`, `cert_chain_pem` |
| private key (PKCS#8) | `exchange_key_pem` | `svid_key_pem`, `private_key_pem`, `key_pem`, `x509_svid_key_pem`, `svid_private_key_pem` |
| trust bundle | `exchange_bundle_pem` | `trust_bundle_pem`, `bundle_pem`, `trust_bundle`, `svid_bundle_pem`, `x509_bundle_pem` |

Each name is looked for at the top level first and then inside `.exchange_svid`,
`.svid` and `.exchange`, in the order above, so the broker's own flat field always
wins. The compatibility list exists only for an out-of-tree broker; nothing in
this repository emits those spellings, and they must never be listed first.

**Why this table is worth reading twice.** The P9 live run listed none of the
canonical names, so a *valid* redemption burned its nonce and then exited `4`
(`evidence/p9/chain-02-field-name-mismatch.txt`). Two consequences are now built
in: the canonical names come first, and a missing field is reported by its exact
JSON key with the burn stated —

```
RESULT phase=p9-bootstrap outcome=ERROR reason=exchange_material_missing \
  missing=exchange_cert_chain_pem,exchange_key_pem,exchange_bundle_pem \
  response_fields=nonce_id,instance_uuid,instance_name,selectors \
  nonce_id=… nonce_state=consumed
```

`response_fields` is the list of top-level key **names** the body did carry —
names only, never values, because the body carries a private key. `nonce_state=consumed`
is the part that matters operationally: the broker answered `200`, single use is
already committed server-side, and a retry needs a freshly minted nonce.

`exchange_spiffe_id` and `exchange_expires_at` are read, printed and cross-checked
against the certificate; the **certificate** wins on any disagreement, because
that is what `x509pop` presents. The binding metadata is read with P8's spellings
(`instance_uuid`/`uuid`, `instance_name`/`name`, `generation`/`generation_uuid`,
`project`) and printed, and `selectors` is printed as a comma-joined list.

### Exit codes

| Exit | Meaning |
| --- | --- |
| `0` | **PASS**: attested, node SPIFFE ID as expected, exchange material reclaimed (or retained on purpose under `EXCHANGE_RETENTION=keep`, which the `RESULT` line states) |
| `2` | usage: an unexpected argument, a missing `SPIRE_SERVER_ADDRESS`, a bad `AGENT_START_MODE`/`AGENT_KEY_MANAGER`, an unreadable file, an unrenderable template |
| `3` | guest socket read failed: key absent (404), forbidden (403), or the socket is unreachable |
| `4` | malformed payload, or malformed/missing exchange material: not PEM, an unparseable key, a key that does not match the certificate, or a certificate with no `spiffe://` URI SAN. **The nonce is already consumed at this point** — the message and the `RESULT` line say so, and name the JSON keys |
| `5` | **fingerprint mismatch — the nonce was NOT sent** |
| `6` | a required binary is missing inside the guest (`reason=missing_dependency dependency=<name>`) |
| `7` | no memory-backed directory could be established. Nothing was requested and the nonce was NOT sent: this script refuses to put an exchange key on a persistent guest filesystem |
| `8` | **the exchange material could not be overwritten and unmounted.** It supersedes every other code, including `0` |
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
`EXCHANGE_RETENTION=keep` ends with `outcome=PASS` and
`exchange_material=kept-by-policy`, never with a claim that anything was
destroyed.

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
- The `KeyManager` block carries the restart tradeoff as a comment, and states
  that the server sets `CanReattest: true` for `x509pop`, because P9 step 4 asks
  for the re-attestation story to be defined rather than discovered.
- `socket_path` carries the non-root decision: SPIRE serves the socket `0777`, so
  reachability is decided by the directories above it, and the bootstrap creates
  every component `0755`.
- `WorkloadAttestor "unix"` is the only workload attestor: nothing
  Incus-specific runs inside the guest. The Incus-derived selectors belong to the
  host agent's `incus-attestor` plugin, one trust boundary further out.
- Placeholder names are listed in the template header **without** their `@@`
  markers so the header stays readable after rendering; the renderer refuses any
  value containing `|` (its `sed` delimiter) and fails if any `@@NAME@@` survives.

## `guest-workload-check.sh`

Fetches with `spire-agent api fetch x509 -write` into a self-mounted tmpfs, reads
the certificate, and overwrites the key the CLI wrote as soon as the certificate
has been parsed. The fetch itself verifies the SVID against the trust bundle
before printing anything, so a successful fetch is a chain check too.

### Root is not the claim: the non-root check

The acceptance is that an in-guest **application** obtains its SVID from a
standard local Workload API. An application is not root, so the root fetch proves
the weaker statement. The script therefore runs the same standard client a second
time as an unprivileged user and reports a **separate verdict** on its own
`RESULT check=issuance-nonroot` line. A root PASS never covers for a non-root
failure: the run ends `outcome=ERROR` with exit `24`.

Two things have to be true for that fetch to succeed, and the script tells them
apart:

1. **Reachability.** SPIRE 1.15.2 serves the Workload API socket mode `0777`
   (observed live: the host agent's socket is `srwxrwxrwx` in
   `evidence/p9/deploy-02-socket-exposure.txt`), so what blocks an unprivileged
   caller is a directory above it. `guest-agent-bootstrap.sh` creates every
   component of `AGENT_SOCKET_PATH` mode `0755` instead of inheriting its own
   `umask 077`, and relaxes an existing non-traversable component with `o+x` only.
   That is not an authorization decision: SPIRE authorizes a workload by attesting
   it against a registration entry's `unix` selectors, never by file mode. If the
   unprivileged user still cannot open the socket, the verdict is
   `reason=socket_unreachable_by_nonroot` — stated plainly, never passed over.
2. **Issuance.** The uid needs a registration entry whose `unix` selectors match
   it. The P9 guest entry is `unix:uid:0`, so an unprivileged fetch against it is
   answered but issued nothing; that is reported as
   `reason=no_entry_for_nonroot_uid socket_reachable=yes`, with the exact
   `spire-server entry create … -selector unix:uid:<uid>` command to fix it. It is
   an **ERROR**, not a pass: reachability was observed, issuance was not.

Set `NONROOT_EXPECTED_SPIFFE_ID` to the ID that entry grants. If the script is
itself started by an unprivileged user, the primary fetch *is* the non-root case
and is reported as `reason=primary_fetch_was_already_nonroot`. `NONROOT_CHECK=skip`
opts out explicitly and warns that the run is not complete evidence for the phase.

Three outcomes, the P8 convention unchanged:

| Outcome | Meaning |
| --- | --- |
| **PASS** | the behavior under test was observed and was correct |
| **FAIL** | it was observed and was wrong: a different SPIFFE ID, or no rotation after the renewal point had passed |
| **ERROR** | nothing was observed: a missing dependency, an unreachable Workload API, a non-root caller that could not be served, or a rotation window longer than this run may wait |

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
| `NONROOT_CHECK` | `run` | `run` fetches again as an unprivileged user; `skip` opts out and records an incomplete run |
| `NONROOT_USER` | `spike-workload` | the unprivileged account; created as a system user with no home and no shell if it does not exist |
| `NONROOT_EXPECTED_SPIFFE_ID` | the root ID | the SPIFFE ID the non-root caller must receive. The P9 root entry is `unix:uid:0`, so this normally needs its own entry |

| Exit | Meaning |
| --- | --- |
| `0` | **PASS**: the expected SPIFFE ID was issued and a rotation was observed |
| `2` | usage: no expected SPIFFE ID, one that is not a `spiffe://` URI, an unexpected argument, a bad `ROTATION_MODE` |
| `6` | a required binary is missing inside the guest |
| `7` | no memory-backed work directory could be established |
| `8` | the fetched material could not be overwritten and unmounted; supersedes every other code |
| `10` | **ERROR** — the Workload API returned nothing usable, or stopped answering mid-wait |
| `20` | **FAIL** — the SVID's SPIFFE ID is not the expected value (also checked again after rotation: a rotation must not change who the workload is) |
| `21` | **FAIL** — the serial did not change after the renewal point plus grace and the minimum observation window: the agent is not rotating |
| `22` | **ERROR** — the rotation window exceeds `ROTATION_MAX_WAIT_SECONDS`, or the validity window could not be parsed |
| `24` | **ERROR** — root was served but a non-root caller was not, so the phase's actual claim is unproven. The `issuance-nonroot` line says which of the two reasons applies |

`RESULT` lines are machine-parseable and there are four of them:

```
RESULT check=issuance outcome=PASS caller=root uid=0 spiffe_id=… serial=… not_before=… not_after=…
RESULT check=issuance-nonroot outcome=PASS user=spike-workload uid=999 spiffe_id=… serial=… socket=…
RESULT check=rotation outcome=PASS mode=poll first_serial=… second_serial=… waited_seconds=… spiffe_id=…
RESULT check=workload outcome=PASS spiffe_id=… socket=… first_serial=… second_serial=… rotation=observed mode=poll nonroot=PASS nonroot_uid=999 material=shredded-and-unmounted
```

and the bootstrap emits one:

```
RESULT phase=p9-bootstrap outcome=PASS nonce_id=… instance_uuid=… \
  exchange_spiffe_id=spiffe://spike.incus.internal/spire-exchange/incus/<uuid> \
  exchange_not_after=… node_spiffe_id=spiffe://spike.incus.internal/spire/agent/x509pop/incus/<uuid> \
  key_manager=memory workload_api=/tmp/spire-agent/public/api.sock \
  exchange_retention=shred exchange_material=shredded-and-unmounted
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
| reclaim | the exchange key does not outlive its single use, and the run says which end state it observed | `exchange_material=shredded-and-unmounted`, `EXCHANGE_DIR` unmounted and empty — or `kept-by-policy`, stated as such |
| socket exposure | the Workload API is reachable by something other than root | `socket=srwxrwxrwx`, every directory component traversable |
| issuance (root) | the API serves the harness itself | the expected workload SPIFFE ID, `caller=root` |
| issuance (non-root) | the phase's actual claim: an in-guest **application** gets its SVID from an ordinary local Workload API with no spike-specific client | the expected SPIFFE ID for `unix:uid:<uid>`, on its own `issuance-nonroot` line; anything else is exit `24` |
| rotation | the agent holds a live relationship with the server rather than a one-shot credential — the basis for the P10 stale-credential cases | the serial changes, the SPIFFE ID does not |

## Harness self-check

The logic in these scripts is exercised end to end against fakes before every
live run — a staged bootstrap payload, a fake TLS broker whose certificate is
pinned by fingerprint, and a fake `spire-agent` — in a privileged Debian 13
container, so the real `mount`/`shred`/`umount`, `mawk`, `jq`, `openssl`,
`useradd` and `runuser` behavior is covered. Verified there for the current
scripts:

- the PASS path end to end with the broker's **canonical** field names
  (`exchange_cert_chain_pem`, `exchange_key_pem`, `exchange_bundle_pem`), and
  again with the nested compatibility spellings;
- a P8-shaped body with no PEM at all exits `4` naming all three missing JSON
  keys, listing the top-level key names that did arrive, and reporting
  `nonce_state=consumed`;
- a malformed `CHAIN_JQ` exits `2` with **zero requests** reaching the broker, so
  no nonce is burned;
- `EXCHANGE_RETENTION=shred` leaves the tmpfs unmounted and the path empty, and a
  restart of the agent then dies with the same
  `unable to load keypair: open /run/spike-exchange/svid.pem: no such file or directory`
  the live run recorded; `EXCHANGE_RETENTION=keep` leaves exactly the three
  credential files, no nonce anywhere, and the restart succeeds;
- the socket directory chain is created `0755` while `/tmp` itself is left at
  `1777`, and an unprivileged user can open the resulting socket;
- the non-root check reports PASS when served, `no_entry_for_nonroot_uid` when the
  API answers but issues nothing, `socket_unreachable_by_nonroot` when the socket
  directory is `0700`, `SKIPPED` under `NONROOT_CHECK=skip`, and exit `6` when
  neither `runuser` nor `su` exists — with exit `24` on every non-root failure.

No transcript from any case contained the nonce value or a PEM private key. Those
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
`node_spiffe_id=`, certificate serials and validity windows, both the
`issuance` and `issuance-nonroot` verdicts, and either
`exchange_material=shredded-and-unmounted` or an explicit
`exchange_material=kept-by-policy`. Those are all permitted evidence under
Appendix D rule 3.

# P8 guest binding and nonce lifecycle harness

**This directory is disposable spike tooling.** Appendix C of `SPIKE_PLAN.md`
classifies everything under `spike/` as never merged as product code: throwaway
configs and operator scripts, deletable without loss, because the evidence they
produce lives in the journal. Nothing here is imported, wrapped, or promoted. The
durable counterparts are `cmd/incus-spiffe-broker`, `internal/nonce`,
`internal/incus/bootstrap`, `internal/incus/identity`, and `internal/broker`.

Three scripts, each parameterized entirely by environment variables with working
defaults, so none of them needs editing:

| Script | Runs where | Purpose |
| --- | --- | --- |
| `operator-mint.sh` | operator host | mint one nonce for an instance UUID and report the public binding metadata |
| `guest-bootstrap.sh` | as root **inside** a guest | read `user.spiffe-bootstrap` from `/dev/incus/sock` and redeem it |
| `lifecycle-matrix.sh` | operator host | drive the P8 step-4 and step-5 cases end to end with a verdict per case |

## Appendix D: no script may print a nonce value

Appendix D of `SPIKE_PLAN.md` is absolute: a nonce value never appears in a log
line, an error, an evidence file, or agent output, and nonce transcripts show
**IDs and hashes only**. The P8 live run captures these scripts' output verbatim,
so each script enforces that rule in code and says why in a header comment:

- `guest-bootstrap.sh` prints the nonce ID, the payload SHA-256, the broker
  fingerprint and HTTP statuses. The payload never enters a shell variable — it
  lives in one mode-0600 file that only `jq` reads. The request body is built by
  `jq` and piped to `curl` on stdin, so the secret never reaches `argv`, which is
  world-readable through `/proc`. Response bodies are never printed raw — a broken
  broker could echo the nonce, and a leaking body is withheld entirely by a guard
  whose `grep` pattern is read from a file rather than the command line. Only
  named, non-secret fields are printed: binding metadata and the frozen `incus:`
  selectors.
- `operator-mint.sh` never prints a response body and **actively asserts** that
  the mint response contains no `nonce`, `secret`, `token` or `password` field. A
  violation exits `20` and reports the offending key paths, never their values.
  That assertion is a live check of the broker contract: the secret must reach the
  guest only through `user.spiffe-bootstrap`.
- `lifecycle-matrix.sh` never sees a nonce at all. When a case needs a payload in
  another place, the bytes move guest-to-guest through a pipe
  (`incus file pull … - | incus file push - …`); they never touch the operator's
  disk. Its cleanup trap removes the guest staging directories that hold payload
  files and clears `user.spiffe-bootstrap`, even when a case aborts.

An operator bearer token, if the broker requires one, is passed through a `curl`
`--config` file for the same reason and is never printed.

## Wire contract these scripts assume

```
POST /v1alpha1/nonce
{"instance_uuid": "…", "project": "…", "ttl_seconds": 120}     ← ttl_seconds optional

201 {"nonce_id": "…", "expires_at": "<RFC3339>", "instance_name": "…",
     "instance_uuid": "…", "generation": "…", "project": "…"}
    and never a nonce field
```

```
POST /v1alpha1/redeem
{"nonce_id": "…", "nonce": "<secret>", "instance_uuid": "<untrusted claim>"}

200 {"nonce_id": "…", "instance_uuid": "…", "instance_name": "…",
     "generation": "…", "project": "…", "selectors": ["incus:…", …]}
```

`instance_uuid` in a redeem request is an **untrusted claim** that the broker must
ignore, resolving only the caller's own binding. Case h exercises exactly that; the
broker's decoder does not reject unknown fields, so the claim is simply discarded.
`ttl_seconds` exists for the expiry case; omit it to use the broker's configured
TTL. Where a field name is cosmetic the scripts accept the obvious alternate
spelling (`name` for `instance_name`, `generation_uuid` for `generation`, `expiry`
for `expires_at`, `uuid` for `instance_uuid`) and print `<absent>` rather than
failing a live run over naming. A `spiffe_id` is printed only if a later phase
starts returning one; P8's redeem answer is binding metadata plus the frozen
`incus:` selectors, with no key material.

Error bodies carry `{"error": "<code>"}` with the broker's stable codes
(`invalid_request`, `unauthorized`, `conflict`, `method_not_allowed`, `internal`,
`unavailable`); the value is echoed into the `RESULT` line as `reason=…`. The
scripts judge on the HTTP status, not on that string:

| Status | Meaning |
| --- | --- |
| **401** | unknown nonce ID **or** wrong secret. One status for both, so a caller cannot enumerate live nonce IDs |
| **409** | the nonce exists and the secret matched, but the state forbids redemption: already used, expired, bound to another instance, generation moved, or the UUID no longer resolves to exactly one instance |
| **400** | the broker could not parse the request or the reference built from the binding |
| **503** | a dependency is unavailable: the nonce store, or the Incus API behind either credential. Retryable, not a rejection |
| **500** | internal fault an operator must fix |

That split is why the lifecycle table below expects **409**, not 401, for the
expiry, deleted-instance and generation cases: those nonces exist and their
secrets match; only their state disqualifies them.

## Guest read shape

Source-pinned to Incus v7.3.0 in `evidence/p8/GUEST_SOCK_BRIEF.md`:

```sh
curl --unix-socket /dev/incus/sock http://localhost/1.0/config/user.spiffe-bootstrap
```

The response is the **raw configured string** with
`Content-Type: application/octet-stream`, no JSON envelope and no trailing
newline. Prerequisites, all of which `lifecycle-matrix.sh` checks in preflight:

- the caller must be guest **root** (containers enforce a peer-UID check, VMs rely
  on socket mode 0600);
- a container needs `security.guestapi` not set to false;
- a **VM needs `incus-agent` running**, or `/dev/incus/sock` does not exist;
- only `user.*` and `cloud-init.*` keys are visible, so a guest cannot read
  `volatile.uuid` or `volatile.uuid.generation` and cannot prove its own identity.
  The broker resolves the UUID binding server-side. That is why an unused nonce is
  a bearer credential — see case i.

A missing key answers HTTP 404; a forbidden key or `security.guestapi=false`
answers HTTP 403. The guest cannot write or clear the key, so single use is
enforced entirely server-side.

## Running the scripts

### `operator-mint.sh`

```sh
BROKER_URL=https://10.42.0.10:8443 \
BROKER_CACERT=/etc/spike/broker-ca.pem \
./operator-mint.sh e9e6a2a0-d695-42d3-8e8c-92d290bfc7da spike-spiffe
```

Prints the nonce ID, expiry, resolved instance name, generation UUID, resolved
UUID and project, then a machine-readable `RESULT mint …` line. The UUID may also
be supplied as `INSTANCE_UUID`; the project defaults to `spike-spiffe`.

| Variable | Default | Purpose |
| --- | --- | --- |
| `BROKER_URL` | `https://spike-broker:8443` | broker base URL, must be `https` |
| `NONCE_PATH` | `/v1alpha1/nonce` | mint endpoint path |
| `INSTANCE_UUID` | — | target `volatile.uuid`; the first positional argument wins |
| `PROJECT` | `spike-spiffe` | Incus project; the second positional argument wins |
| `MINT_TTL_SECONDS` | unset | request a specific TTL (used by lifecycle case c) |
| `BROKER_CACERT` | unset | spike CA used for chain validation; strongly recommended |
| `BROKER_FINGERPRINT` | unset | additionally pin the broker leaf certificate by SHA-256 |
| `BROKER_TLS_HOSTNAME` | unset | certificate SAN to validate against, via `--connect-to` |
| `ALLOW_INSECURE_TLS` | `0` | explicit opt-in to disable chain validation, with a warning |
| `MINT_AUTH_TOKEN_FILE` | unset | operator bearer token read from a file (preferred) |
| `MINT_AUTH_TOKEN` | unset | operator bearer token from the environment |
| `CURL_BIN` `JQ_BIN` `OPENSSL_BIN` | `curl` `jq` `openssl` | binaries |
| `CONNECT_TIMEOUT` `MAX_TIME` | `5` `20` | curl timeouts, seconds |

Exit codes: `0` minted, `2` usage or dependency, `5` fingerprint mismatch, `14`
non-2xx status, `15` transport failure, `20` **contract violation: the response
carried a secret**, `21` unusable response (not JSON, or no `nonce_id`).

At least one of `BROKER_CACERT`, `BROKER_FINGERPRINT` or `ALLOW_INSECURE_TLS=1` is
required; the script refuses to talk to an unvalidated broker.

### `guest-bootstrap.sh`

Runs as root inside the guest. `lifecycle-matrix.sh` pushes and invokes it for
you; run it by hand like this:

```sh
incus file push guest-bootstrap.sh spike-guest-a/root/guest-bootstrap.sh --mode 0700
incus exec spike-guest-a -- env BROKER_CACERT=/root/broker-ca.pem \
  /root/guest-bootstrap.sh
```

| Variable | Default | Purpose |
| --- | --- | --- |
| `MODE` | `redeem` | `redeem` posts the nonce; `fetch` only reports and optionally stages the payload |
| `GUEST_SOCKET` | `/dev/incus/sock` | guest API socket |
| `BOOTSTRAP_KEY` | `user.spiffe-bootstrap` | configuration key to read |
| `PAYLOAD_FILE` | unset | read the payload from this file instead of the socket |
| `PAYLOAD_OUT` | unset | persist the raw payload here, mode 0600 |
| `CLAIM_UUID` | unset | add an untrusted `instance_uuid` claim to the redeem body |
| `BROKER_URL_OVERRIDE` | unset | override the payload's `broker_url` |
| `REDEEM_PATH` | `/v1alpha1/redeem` | redeem endpoint path |
| `BROKER_CACERT` | unset | spike CA for chain validation, inside the guest |
| `BROKER_TLS_HOSTNAME` | unset | certificate SAN to validate against |
| `ALLOW_INSECURE_TLS` | `0` | explicit opt-in to disable chain validation, with a warning |
| `CURL_BIN` `JQ_BIN` `OPENSSL_BIN` | `curl` `jq` `openssl` | binaries; `openssl` is required for pinning |
| `CONNECT_TIMEOUT` `MAX_TIME` | `5` `20` | curl timeouts, seconds |

Exit codes: `0` granted or fetched, `2` usage or dependency, `3` guest socket read
failed, `4` malformed payload, `5` **fingerprint mismatch — the nonce is not
sent**, `10` HTTP 401, `11` HTTP 409, `12` HTTP 500, `13` HTTP 503, `14` HTTP 400,
another unexpected status, or a response that echoed the secret, `15` transport
failure.

#### How the broker certificate is pinned

The payload carries `broker_fingerprint`, the SHA-256 of the broker's leaf
certificate. `curl` cannot pin a certificate digest — `--pinnedpubkey` pins the
SHA-256 of the SubjectPublicKeyInfo — so the script does this:

1. fetches the leaf with `openssl s_client` and compares its SHA-256 with the
   payload value. A mismatch aborts with exit `5` **before the nonce is sent**;
2. derives the SPKI hash of that same certificate and passes it to `curl` as
   `--pinnedpubkey sha256//…`, so the request must reach the certificate that was
   just verified;
3. validates the chain with `--cacert "$BROKER_CACERT"` when a CA is supplied.
   Without one it uses the fetched leaf as its own trust anchor, which works only
   for a self-signed broker certificate.

`ALLOW_INSECURE_TLS=1` is an explicit opt-in that disables only curl's chain and
hostname validation; the fingerprint comparison and the SPKI pin still run, and
the script prints a warning telling you to record that the run did not prove chain
validation. Supply `BROKER_CACERT` instead whenever you can.

### `lifecycle-matrix.sh`

```sh
INCUS_REMOTE=ovh-incusos \
PROJECT=spike-spiffe \
GUEST_A=spike-guest-a GUEST_B=spike-guest-b \
BROKER_URL=https://10.42.0.10:8443 \
BROKER_CACERT=/etc/spike/broker-ca.pem \
./lifecycle-matrix.sh
```

Exits `0` when every selected case behaves, `1` when any case misbehaves, `2` on a
preflight failure. Preflight resolves both UUIDs, proves both guests expose
`/dev/incus/sock`, and stages the guest harness plus the CA in a 0700 directory
inside each guest.

| Variable | Default | Purpose |
| --- | --- | --- |
| `INCUS_BIN` | `incus` | Incus client binary |
| `INCUS_REMOTE` | `ovh-incusos` | remote name; empty string drives the local daemon |
| `PROJECT` | `spike-spiffe` | Incus project |
| `GUEST_A` / `GUEST_B` | `spike-guest-a` / `spike-guest-b` | the two guests |
| `GUEST_A_UUID` / `GUEST_B_UUID` | resolved from `volatile.uuid` | override only to test a stale UUID |
| `TMP_INSTANCE` | `spike-guest-tmp` | disposable instance for case e; **it is deleted** |
| `TMP_IMAGE` | `images:debian/13` | image for that instance |
| `TMP_TYPE` | `container` | `container` or `vm`; `vm` needs `incus-agent` in the image |
| `BROKER_URL` | `https://spike-broker:8443` | broker URL used for minting |
| `GUEST_BROKER_URL` | unset | override the payload URL inside guests (split-horizon bridge only) |
| `NONCE_PATH` / `REDEEM_PATH` | `/v1alpha1/nonce` / `/v1alpha1/redeem` | endpoint paths |
| `BROKER_CACERT` | unset | spike CA; pushed into each guest as `broker-ca.pem` |
| `BROKER_FINGERPRINT` | unset | operator-side certificate pin for minting |
| `BROKER_TLS_HOSTNAME` | unset | certificate SAN to validate against |
| `ALLOW_INSECURE_TLS` | `0` | explicit opt-in, propagated to the guest harness |
| `MINT_AUTH_TOKEN_FILE` / `MINT_AUTH_TOKEN` | unset | operator bearer token |
| `MINT_TTL_SECONDS` | unset | TTL for every case except c |
| `SHORT_TTL_SECONDS` | `5` | TTL requested for case c |
| `EXPIRY_WAIT_SECONDS` | `SHORT_TTL_SECONDS + 3` | wait before the expired redemption |
| `BOOTSTRAP_KEY` | `user.spiffe-bootstrap` | configuration key under test |
| `GUEST_STAGE_DIR` | `/root/p8` | 0700 staging directory inside each guest |
| `GUEST_READY_TIMEOUT` | `180` | seconds to wait for `/dev/incus/sock` |
| `CASES` | `a b c d e f g h i` | subset and order of cases to run |
| `STRICT_STATUS` | `0` | `1` turns unexpected-status notes into failures |
| `KEEP_ARTIFACTS` | `0` | `1` keeps the staging dirs, snapshot and temp instance — **they contain nonce payloads** |
| `HARNESS_DIR` | this directory | where the other two scripts are found |
| `CURL_BIN` `JQ_BIN` `OPENSSL_BIN` | `curl` `jq` `openssl` | operator-side binaries |

If the broker ignores `ttl_seconds`, case c would otherwise measure nothing: set
`EXPIRY_WAIT_SECONDS` above the broker's configured TTL. The script prints the
mint's `expires_at` so you can see which TTL actually applied.

## What each case proves

| Case | Proves | Expected outcome |
| --- | --- | --- |
| a | the intended path end to end: the broker writes the key, the guest reads it through its own socket, the broker resolves A and grants an identity | HTTP **200**, `instance_uuid` = A |
| b | single use for a sequential retry | HTTP **409** |
| c | expiry is enforced server-side even though the guest can still read the key | HTTP **409** |
| d | the consume is atomic: two concurrent redemptions of one nonce | exactly one HTTP **200**, the other HTTP **409** |
| e | a nonce cannot outlive its instance; P6 makes names reusable, so the UUID is re-resolved at redemption and resolves to nothing | HTTP **409** |
| f | a generation change invalidates the binding; P6 proved a snapshot restore always installs a fresh `volatile.uuid.generation` | HTTP **409** |
| g | delivery is per-instance: B's own `/dev/incus/sock` exposes only B's configuration | guest API HTTP **404** in B (403 if `security.guestapi` is off) |
| h | the claimed `instance_uuid` is untrusted input: B presents B's nonce and asks for A's identity | HTTP **200** resolving **B**, never A |
| i | **measurement, not a pass/fail case** — see below | HTTP **200** granting A's identity |

Cases a–h fail the run only on a wrong security outcome: a rejection that was
granted, a grant with the wrong identity, or a concurrency result other than
exactly one success. A rejection carrying an unexpected status code is a `NOTE`,
because reject-versus-grant is the security property and the status code is a
contract detail; `STRICT_STATUS=1` promotes those notes to failures.

Case g compares payload SHA-256 digests rather than values: if B ever did read a
bootstrap value, a digest equal to A's proves it read A's nonce, and the harness
fails the case without printing either value.

### Case i is expected to SUCCEED

`SPIKE_PLAN.md` P8 step 5 states it outright: "A deliberately leaked, unused A
nonce is a bearer credential and can impersonate A unless the prototype adds
another caller-binding mechanism; measure and record that limitation instead of
expecting rejection." `GUEST_SOCK_BRIEF.md` section 6 reaches the same conclusion
from the guest side: a guest cannot learn its own UUID or generation, so
possession of the payload is the only proof it can present, and that proof is not
bound to the calling VM's transport.

So case i copies A's **unused** nonce into B and redeems it from B. A success is
the expected result. The harness labels the outcome `MEASURED`, records it as the
bearer-token risk and a **go/no-go input** for the P8 acceptance record, and never
lets it change the exit status. Acceptance for P8 is that cases a–h behave, plus an
honest record of case i — not that case i fails.

If case i is ever rejected, that is also recorded as `MEASURED`, with a prompt to
document what extra caller binding the prototype gained, because it contradicts
the plan's expectation.

## Cleanup

`lifecycle-matrix.sh` installs an `EXIT` trap that runs on abort too, satisfying
P8's rollback requirement that config keys are cleared either way. It clears
`user.spiffe-bootstrap` on both guests, deletes the snapshot it created, force
deletes `TMP_INSTANCE`, and removes `GUEST_STAGE_DIR` inside every guest it
prepared, because those directories hold nonce payloads. `KEEP_ARTIFACTS=1`
suppresses that; if you use it, clear those directories by hand before capturing
evidence.

The broker's own nonce store is server-side and cannot be cleared from here. With
the in-memory store, restarting the broker discards every outstanding record.

## Before capturing evidence

Appendix D rule 4 asks for a pre-commit check on every evidence file. For a
transcript produced here, search it for PEM `PRIVATE KEY` blocks, base64 blobs
longer than 64 characters, and the strings `recovery` and `nonce=`. A transcript
from these scripts should contain `nonce_id=`, `payload_sha256=`,
`broker_fingerprint=`, `selectors=incus:…` and `nonce=<redacted…>` — and no bare
`nonce=` value. Selectors, UUIDs, generations and fingerprints are all permitted
evidence under Appendix D rule 3.

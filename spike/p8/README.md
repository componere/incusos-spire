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
  files and clears `user.spiffe-bootstrap`, even when a case aborts — and it
  **verifies** the clear by piping `incus config get` straight into `grep -q`, so
  even the check never captures the value it is looking for.

The operator bearer token the mint endpoint requires is passed through a `curl`
`--config` file for the same reason and is never printed.

## Wire contract these scripts assume

```
POST /v1alpha1/nonce
Authorization: Bearer <operator token>                       ← required
{"instance_uuid": "…", "project": "…", "ttl_seconds": 120}   ← ttl_seconds optional, bounded

201 {"nonce_id": "…", "expires_at": "<RFC3339>", "instance_name": "…",
     "instance_uuid": "…", "generation": "…", "project": "…"}
    and never a nonce field
```

```
POST /v1alpha1/redeem
{"nonce_id": "…", "nonce": "<secret>", "broker_url": "…", "broker_fingerprint": "…"}
                 …plus "instance_uuid": "<claim>"  → 400, the claim is refused

200 {"nonce_id": "…", "instance_uuid": "…", "instance_name": "…",
     "generation": "…", "project": "…", "selectors": ["incus:…", …]}
```

`instance_uuid` in a redeem request is a caller-supplied identity claim that must
never decide the binding. The broker resolves the binding server-side from the
nonce record and its decoder **refuses** an `instance_uuid` field with `400`, so
the claim is not merely ignored, it is not accepted at all. Case h accepts either
answer — a `200` resolving B, or a `400` followed by the same nonce still
resolving B and only B — and fails only if B ever obtains A's identity. The
redeem body may carry the four payload fields verbatim (`nonce_id`, `nonce`,
`broker_url`, `broker_fingerprint`); the last two are accepted and ignored.

Both decoders are **strict**: an unknown field is an HTTP `400`, not a silently
dropped value — which is how `ttl_seconds` came to be advertised and ignored in
the first place. `ttl_seconds` is optional and must be a positive integer that
does not exceed the broker's `-max-nonce-ttl` (which defaults to `-nonce-ttl`).
A value outside that range is **refused with `400`, not clamped**, precisely
because an operator who asks for a five-second window and silently receives ten
minutes has been told something untrue about a bearer credential. An accepted
`ttl_seconds` applies exactly, and the returned `expires_at` remains the record
of what applied. `operator-mint.sh` sends the field only when `MINT_TTL_SECONDS`
is set, refuses a non-integer value locally rather than splicing it into the
request, and prints the requested TTL beside the returned `expires_at`.
`lifecycle-matrix.sh` derives the case-c expiry wait from that `expires_at`
rather than from what it asked for.

The mint endpoint is **authenticated**: it compares the presented bearer token
against the digest of the broker's `-mint-token-file` and answers `401` with a
`WWW-Authenticate` challenge otherwise. `lifecycle-matrix.sh` refuses to start
without `MINT_AUTH_TOKEN_FILE` or `MINT_AUTH_TOKEN`; `operator-mint.sh` will run
without one and warns, so the `401` refusal itself can be demonstrated.

Where a field name is cosmetic the scripts accept the obvious alternate
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
| **400** | the broker refused the request body: an unknown field, an `instance_uuid` claim on a redeem, a `ttl_seconds` outside its range, or a reference it could not build from the binding |
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
| `MINT_TTL_SECONDS` | unset | request a TTL (lifecycle case c). A positive integer; unset means the field is not sent. The broker caps it, so `expires_at` in the response is the applied TTL |
| `BROKER_CACERT` | unset | spike CA used for chain validation; strongly recommended |
| `BROKER_FINGERPRINT` | unset | additionally pin the broker leaf certificate by SHA-256 |
| `BROKER_TLS_HOSTNAME` | unset | certificate SAN to validate against, via `--connect-to` |
| `ALLOW_INSECURE_TLS` | `0` | explicit opt-in to disable chain validation, with a warning |
| `MINT_AUTH_TOKEN_FILE` | unset | operator bearer token read from a file (preferred); the mint endpoint requires one |
| `MINT_AUTH_TOKEN` | unset | operator bearer token from the environment; without either, expect `401` |
| `CURL_BIN` `JQ_BIN` `OPENSSL_BIN` | `curl` `jq` `openssl` | binaries |
| `CONNECT_TIMEOUT` `MAX_TIME` | `5` `20` | curl timeouts, seconds |

Exit codes: `0` minted, `2` usage, a missing operator dependency or a
`MINT_TTL_SECONDS` that is not a positive integer, `5` fingerprint mismatch, `14`
non-2xx status (a `400` now also means the strict mint decoder rejected an
unknown field or an out-of-bounds `ttl_seconds`), `15` transport failure, `20`
**contract violation: the response carried a secret**, `21` unusable response
(not JSON, or no `nonce_id`).

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

Exit codes: `0` granted or fetched, `2` usage, `6` **a required binary is missing
inside the guest** — reported as `RESULT … reason=missing_dependency
dependency=<name>` so the matrix can record ERROR rather than invent a security
verdict, `3` guest socket read failed, `4` malformed payload, `5` **fingerprint
mismatch — the nonce is not sent**, `10` HTTP 401, `11` HTTP 409, `12` HTTP 500,
`13` HTTP 503, `14` HTTP 400, another unexpected status, or a response that
echoed the secret, `15` transport failure.

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
MINT_AUTH_TOKEN_FILE=/etc/spike/mint-token \
./lifecycle-matrix.sh
```

#### Three outcomes, and what the exit status means

A verdict is only evidence if it separates "the control decided correctly" from
"the control never got to decide". Every case ends in exactly one outcome:

| Outcome | Meaning |
| --- | --- |
| **PASS** | the security decision under test was observed and was correct |
| **FAIL** | the decision was observed and was **wrong**: a rejection that was granted, a grant with the wrong identity, or a concurrency result other than exactly one success |
| **ERROR** | **no decision was observed.** A precondition, a dependency or the backend failed: a missing guest binary, a socket that never came up, a mint that never happened, HTTP `000`/`400`/`500`/`503` where only a `401`/`409` would have been a judgement |
| **MEASURED** | case i only: a recorded observation of a known limitation, neither pass nor failure |

An ERROR is **never** printed as a PASS and always makes the run exit non-zero.
A rejection carrying an unexpected but still meaningful status (`401` where `409`
was documented) stays a `NOTE`, because reject-versus-grant is the security
property and the code is a contract detail; `STRICT_STATUS=1` promotes those
notes to failures. A status that is not a decision at all is an ERROR whatever
`STRICT_STATUS` says.

The run ends with a summary table listing every selected case with its outcome
and one-line detail, then:

| Exit | Meaning |
| --- | --- |
| `0` | every selected case passed (case i measured) |
| `1` | at least one case FAILed or ERRORed |
| `2` | preflight or usage failure |
| `3` | **cleanup was incomplete** — a nonce secret or a payload file may still be live |

`ALLOW_CASE_ERRORS=1` is the only opt-out: errors are still printed and still
listed, but they stop forcing exit `1`, and the summary states that the run is
**not complete evidence**. Do not use it for an evidence run.

#### Preflight and the guest dependency check

Preflight requires an operator mint credential, resolves both UUIDs, and then
assesses each guest once: the instance exists, `/dev/incus/sock` is up, every
binary in `GUEST_DEPS` (`curl jq openssl`)
is present inside it, and `guest-bootstrap.sh` plus the CA stage into a 0700
directory. A guest that fails any of those is not fatal — every case that needs
it is recorded as **ERROR naming the exact missing dependency**, which is what
the P8 live run needed when stock `images:debian/13` turned out to have no `jq`
and case e died with a bare `exit 2`. The disposable case-e instance is assessed
the same way, right after it is launched.

`GUEST_INSTALL_DEPS=1` is the explicit opt-in that installs what is missing with
`GUEST_INSTALL_CMD` (`apt-get … --no-install-recommends`, so Debian and Ubuntu
guests) and re-checks before continuing. It **mutates the guest**, is never
implicit, and prints a line telling you to record it in the evidence inventory.

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
| `MINT_AUTH_TOKEN_FILE` / `MINT_AUTH_TOKEN` | unset | operator bearer token; **required** — preflight fails without one |
| `MINT_TTL_SECONDS` | unset | `ttl_seconds` for every case except c; unset means the field is not sent |
| `SHORT_TTL_SECONDS` | `5` | `ttl_seconds` requested for case c |
| `EXPIRY_WAIT_SECONDS` | derived from the mint's `expires_at`, `+3s` | override the wait before the expired redemption |
| `MAX_EXPIRY_WAIT_SECONDS` | `120` | if the applied TTL needs a longer wait than this, case c is an **ERROR** instead of a ten-minute hang |
| `BOOTSTRAP_KEY` | `user.spiffe-bootstrap` | configuration key under test |
| `GUEST_STAGE_DIR` | `/root/p8` | 0700 staging directory inside each guest |
| `GUEST_READY_TIMEOUT` | `180` | seconds to wait for `/dev/incus/sock` |
| `GUEST_DEPS` | `curl jq openssl` | binaries `guest-bootstrap.sh` needs inside each guest |
| `GUEST_INSTALL_DEPS` | `0` | `1` installs the missing ones with `GUEST_INSTALL_CMD`; **mutates the guest** |
| `GUEST_INSTALL_CMD` | `apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends` | installer, with the missing package names appended |
| `CASES` | `a b c d e f g h i` | subset and order of cases to run |
| `STRICT_STATUS` | `0` | `1` turns unexpected-status notes into failures |
| `ALLOW_CASE_ERRORS` | `0` | `1` reports ERROR cases without failing the run — **the run is then not complete evidence** |
| `KEEP_ARTIFACTS` | `0` | `1` keeps the staging dirs, snapshot and temp instance — **they contain nonce payloads**. It never suppresses the verified clearing of the bootstrap key |
| `HARNESS_DIR` | this directory | where the other two scripts are found |
| `CURL_BIN` `JQ_BIN` `OPENSSL_BIN` | `curl` `jq` `openssl` | operator-side binaries |

`ttl_seconds` is bounded by the broker, so case c does not trust what it asked
for: it derives the wait from the `expires_at` the broker returned, notes when
the applied TTL is longer than requested, and records an **ERROR** rather than a
PASS if the wait would exceed `MAX_EXPIRY_WAIT_SECONDS`. Set
`EXPIRY_WAIT_SECONDS` to override the derivation entirely.

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
| h | the claimed `instance_uuid` never decides the binding: B presents B's nonce and asks for A's identity | HTTP **200** resolving **B**, or **400** refusing the claim and then **200** resolving B — never A |
| i | **measurement, not a pass/fail case** — see below | HTTP **200** granting A's identity |

Cases a–h FAIL only on a wrong security outcome: a rejection that was granted, a
grant with the wrong identity, or a concurrency result other than exactly one
success. They report **ERROR** whenever the outcome above was not observed at
all, specifically when:

- a guest is missing a dependency, has no socket, or cannot be staged;
- the mint did not produce a nonce, so there was nothing to redeem;
- a rejection arrived as `000`, `400`, `500`, `503` or any other non-decision,
  rather than the `401`/`409` that means the broker actually judged the nonce;
- case a is granted without a resolved `instance_uuid`, so the binding cannot be
  checked;
- case c would have to wait longer than `MAX_EXPIRY_WAIT_SECONDS`, meaning the
  requested `ttl_seconds` did not apply;
- case d has one success but the loser never reached a decision, so atomicity is
  unproven;
- case f's snapshot restore did not install a fresh generation, contradicting P6;
- case g's guest-B read fails for any reason other than the guest API's own `404`
  or `403` — a dead socket proves nothing about isolation;
- case h's redemption fails for a reason other than the refused claim (`401`,
  `409`, `5xx`, `000`), so the claim was never judged, or the claim is refused
  with `400` and B's own unclaimed nonce then fails too, which the harness cannot
  tell apart from a broken redemption. A `200` with no resolved `instance_uuid`
  is an ERROR for the same reason: nothing says whose identity B received.

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
bearer-token risk and a **go/no-go input** for the P8 acceptance record, and
neither a success nor a rejection changes the exit status. Acceptance for P8 is
that cases a–h behave, plus an honest record of case i — not that case i fails.

If case i is ever rejected, that is also recorded as `MEASURED`, with a prompt to
document what extra caller binding the prototype gained, because it contradicts
the plan's expectation.

Failing to measure case i at all — a missing dependency, a mint that failed, a
redemption that never reached the broker — is an **ERROR** like anywhere else. It
leaves the go/no-go record incomplete, so it does affect the exit status. Only the
measurement itself is exempt.

## Cleanup

`lifecycle-matrix.sh` installs an `EXIT` trap that runs on abort too, satisfying
P8's rollback requirement that config keys are cleared either way. Every step is
checked, every remaining step is still attempted after one fails, and an
incomplete cleanup exits **`3`** even when every case passed — "we tried" is not
the requirement, "it is gone" is. Cleanup:

1. clears `user.spiffe-bootstrap` on **every instance the run touched** — both
   guests and the disposable case-e instance — and **verifies** each one by
   reading the key back. The read is piped straight into `grep -q`, so the check
   never captures or prints the value. A key that survives, or a read-back that
   fails, is reported by name with the exact `incus config unset` command to run;
2. deletes every snapshot it created;
3. force deletes `TMP_INSTANCE` when a case left one behind;
4. removes `GUEST_STAGE_DIR` inside every guest it prepared, because those
   directories hold raw payload files, and verifies the directory is gone.

`KEEP_ARTIFACTS=1` keeps the snapshot, the disposable instance and the staging
directories for debugging — an explicit choice that does not by itself fail the
run, but the staging directories hold nonce payloads, so clear them by hand
before capturing evidence. It never suppresses step 1: a live nonce is not a
debugging aid.

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

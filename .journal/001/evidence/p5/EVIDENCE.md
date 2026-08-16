# P5 — Incus API authentication and least-privilege model

- **Captured:** 2026-08-16 16:44 PDT
- **Host:** `ovh-incusos:` — `147.135.105.83:8443`, server name `ns1001912.ip-147-135-105.us`, IncusOS, kernel `7.1.8-zabbly+`, storage `zfs`
- **Versions:** Incus server 7.3, client 7.2, 541 API extensions
- **Phase agent:** P5AuthzModel

## Scope

Determine the minimum Incus 7.3 authorization surface for two separate identities:

- `spike-attestor-ro` — read-only instance queries in project `spike-spiffe`.
- `spike-bootstrap-writer` — set/clear `user.spiffe-bootstrap` on instances in `spike-spiffe`.

In scope: project `spike-spiffe`, container `spike-authz-probe`, the two TLS identities, and the server-level authorization mechanism. Out of scope and untouched: TPM, SPIRE, plugin code, instance UUID lifecycle semantics (P6), project `spike-uuid-lab` (P6-owned).

The four protected `default`-project containers (`spire-server`, `spire-agent`, `spike-probe`, `spike-p3-stage`) were never modified. Verified RUNNING at phase end — see [`final-state.txt`](final-state.txt).

## Acceptance result

| # | Plan acceptance criterion | Result | Evidence |
|---|---|---|---|
| 1 | Required-operations table | **PASS** | [Required operations](#required-operations) — all 7 attestor reads resolve in one API call |
| 2 | Mechanism matrix for what Incus 7.3 can/cannot express | **PASS** | [Mechanism matrix](#mechanism-matrix) |
| 3 | Allowed/denied transcripts, verbatim, every adversarial case | **PASS** | [`matrix2-attestor-ro-scriptlet.txt`](matrix2-attestor-ro-scriptlet.txt), [`matrix2-writer-scriptlet.txt`](matrix2-writer-scriptlet.txt), baseline [`matrix-attestor-ro-tls.txt`](matrix-attestor-ro-tls.txt), [`matrix-writer-tls.txt`](matrix-writer-tls.txt) |
| 4 | Two credential recipes, no shared key material | **PASS** | [Credential recipes](#credential-recipes); distinct SHA-256 fingerprints `6ebaf5eb…` / `afd4f608…`, keys generated independently |
| 5 | Read-only instance access for `spike-attestor-ro` | **PASS** | Every write, lifecycle, state, exec and file case denied — see matrix rows B/C/D |
| 6 | Only the bootstrap-key mutation for `spike-bootstrap-writer` | **FAIL (exact) / PARTIAL (smallest achievable)** | Incus cannot express a per-config-key grant. Smallest achievable is `instance:spike-spiffe/* can_edit`, which also permits **delete**, **rename**, and **`volatile.uuid` spoofing**. See [Residual permissions](#residual-permissions) |
| 7 | Record smallest achievable grant + every residual permission | **PASS** | [Residual permissions](#residual-permissions) |
| 8 | `spike-spiffe` exists with `spike-authz-probe` RUNNING; nothing else left behind | **PASS** | [`final-state.txt`](final-state.txt) |

**Gate input:** criterion 6 is the one hard negative result of this phase. It does not block the functional spike, but it is a genuine go/no-go input — see [Handoff](#handoff).

## Required operations

### Attestor reads

All seven fields the attestor needs come from **one** authenticated API call. There is no need for `incus config get`, and no need to read images, profiles, storage or host resources.

```
GET /1.0/instances?recursion=1&project=spike-spiffe&filter=config.volatile.uuid eq <uuid>
```

| Field needed | Source | Where it comes from |
|---|---|---|
| instance existence by `volatile.uuid` | `filter=config.volatile.uuid eq <uuid>` on `/1.0/instances` | server-side filter; empty array `[]` when no match |
| project | `.project` | top-level field of the instance record |
| type | `.type` (`container` / `virtual-machine`) | top-level field |
| status | `.status` + `.status_code` | top-level field |
| location | `.location` (`none` on this non-clustered host) | top-level field |
| `volatile.uuid.generation` | `.config."volatile.uuid.generation"` | instance `config` map |
| image fingerprint | `.config."volatile.base_image"` | instance `config` map |

Observed for the probe:

```json
{
  "name": "spike-authz-probe",
  "project": "spike-spiffe",
  "type": "container",
  "status": "Running",
  "location": "none",
  "uuid": "6d1c5ee3-5b2f-4ead-8e54-db985302fbdb",
  "gen": "6d1c5ee3-5b2f-4ead-8e54-db985302fbdb",
  "img": "f005c3b83cc4ffe5b0e0a0c3fccdee6decbae5559fafce9861d9c8b3d2720a16"
}
```

Notes:

- The image fingerprint key is `volatile.base_image`. `image.id` (`debian:trixie`) is a human label, not a fingerprint, and `image.*` keys are copied from the source image — do not treat them as authoritative.
- Non-matching UUID returns `[]`, not an error — existence checks are unambiguous.
- Without `recursion=1` the same filter returns only URLs: `["/1.0/instances/spike-authz-probe?project=spike-spiffe"]`.
- `incus config get` is a client-side convenience over the same `GET`; it needs the same `can_view` entitlement. Nothing requires it.

### Bootstrap write

One operation, expressed as a raw PATCH so it needs **no read**:

```
PATCH /1.0/instances/<name>?project=spike-spiffe   {"config":{"user.spiffe-bootstrap":"<token>"}}   # set
PATCH /1.0/instances/<name>?project=spike-spiffe   {"config":{"user.spiffe-bootstrap":""}}          # clear
```

Verified: PATCH with `""` **removes** the key rather than leaving it empty — after clearing, `.config | has("user.spiffe-bootstrap")` is `false`.

`incus config set` / `incus config unset` also work but perform a read-modify-write and therefore additionally require `can_view` on the instance. Using the raw PATCH is what makes a genuinely write-only credential possible.

## Mechanism matrix

Investigated in the order the task prescribed.

| Mechanism | Available on Incus 7.3? | Evidence |
|---|---|---|
| (a) `incus auth identity` / `auth group` / `auth permission` | **NO — does not exist** | `incus auth --help` → `Error: unknown command "auth" for "incus"`. `/1.0/auth`, `/1.0/auth/identities`, `/1.0/auth/groups`, `/1.0/auth/permissions` all → `Error: not found`. No `access_management` API extension in the 541 reported. This is an LXD feature; Incus did not adopt it. |
| (b) Project-restricted TLS certificates | Yes, but far too coarse | `incus config trust add-certificate … --restricted --projects spike-spiffe`. Grants full project-operator rights. |
| (c) Authorization **scriptlet** (Starlark) | **Yes — this is Incus's fine-grained mechanism** | `authorization.scriptlet` + `authorization.client.tls-restricted=scriptlet`. API extensions `authorization_scriptlet`, `authorization_scriptlet_cert`, `authorization_client_routing`. |
| (d) OpenFGA | Available, not used | Requires running an external OpenFGA server. Rejected as disproportionate for this spike; the scriptlet expresses the same model locally. |

**Mechanism used: (c), layered on top of (b).** Rationale: (a) does not exist; (b) alone fails the plan's adversarial requirements outright; (c) is the only in-tree way to express read-only and write-only grants. The certificates remain `--restricted --projects spike-spiffe` so that the restriction is still recorded in the trust store and the scriptlet can verify it.

### What mechanism (b) alone actually grants — measured, not assumed

Both identities were tested with plain restricted TLS before any scriptlet existed. **The two identities were indistinguishable** — identical results across all 34 cases ([`matrix-attestor-ro-tls.txt`](matrix-attestor-ro-tls.txt), [`matrix-writer-tls.txt`](matrix-writer-tls.txt)).

| Behaviour under restricted TLS | Observed |
|---|---|
| Read instances in `spike-spiffe` | ALLOWED (intended) |
| Write **any** instance config key, including `security.privileged` | ALLOWED — **residual** |
| Create instance | ALLOWED — **residual** ([`matrix-attestor-ro-lifecycle.txt`](matrix-attestor-ro-lifecycle.txt)) |
| Delete instance | ALLOWED — **residual** |
| Stop instance | ALLOWED — **residual** (it stopped the probe mid-run) |
| Pull files out of the instance | ALLOWED — **residual** (`incus file pull …/etc/hostname` → `debuerreotype`) |
| Edit the project's `default` profile | ALLOWED — **residual** |
| Read `/1.0/resources` (host CPU model, RAM, disk serials, NICs) | ALLOWED — **residual** ([`host-surface-detail.txt`](host-surface-detail.txt)) |
| List storage pools, list trust-store certificate fingerprints | ALLOWED — **residual** |
| Read another project's instances | denied: `Error: User does not have permission for project "default"` |
| Server config write, create project, add certificate, warnings | denied: `Error: Certificate is restricted` |

Project confinement works well under (b); *intra-project* confinement does not exist at all. A restricted certificate is a project operator.

**Conclusion:** mechanism (b) alone fails plan step 4 on every count — it cannot deny create, delete, or writes, and cannot separate the two identities. Given P6's finding that `volatile.uuid` is freely writable, a restricted-TLS attestor credential could spoof the very identity anchor it exists to verify.

### What the scriptlet can and cannot express

| Requirement | Expressible? | Detail |
|---|---|---|
| Read-only instance access, one project | **Yes, exactly** | `object.startswith("instance:spike-spiffe/") and entitlement == "can_view"` |
| Deny create / delete / stop / exec / file access | **Yes** | Distinct entitlements: `can_create_instances`, `can_update_state`, `can_exec`, `can_connect_sftp` |
| Confine to one project | **Yes, but you must write it yourself** | See warning below |
| Write **one** config key only | **NO** | The scriptlet receives only `(details, object, entitlement)`. The request **body is never passed**, so `user.spiffe-bootstrap` and `volatile.uuid` are the same question: `instance:spike-spiffe/<name> can_edit` |
| Allow config write but deny delete | **NO** | DELETE and PATCH both authorize as `can_edit`; there is no delete entitlement. Proven: the writer holds *only* `can_edit` and `DELETE /1.0/instances/spike-authz-victim` succeeded |
| Deny the client handshake but keep instance reads | **NO** | `server:incus can_view` is irreducible ([`minimal-grant-experiment.txt`](minimal-grant-experiment.txt)) |

**Critical deployment warning, confirmed live.** Routing `tls-restricted` to anything other than `tls` makes Incus **stop consulting the certificate's project list**. During the discovery pass the attestor certificate was asked for — and granted — `can_view` on `instance:default/spire-server` and on P6's `instance:spike-uuid-lab/lab-c2`, despite being restricted to `spike-spiffe`. Those were read-only calls and nothing was modified, but it proves the hazard. The final scriptlet re-implements confinement itself and additionally requires `cert.restricted` and `PROJECT in cert.projects`.

### Live scriptlet contract (upstream docs are wrong)

Full transcript: [`authz-vocabulary.txt`](authz-vocabulary.txt).

The server validates the function on write:

```
$ incus config set ovh-incusos: authorization.scriptlet="# empty"
Error: cannot set 'authorization.scriptlet' to '# empty': the function "authorize" is required but has not been found in the scriptlet
```

```
$ printf 'def authorize(a):\n    return True\n' | incus config set ovh-incusos: authorization.scriptlet -
Error: cannot set 'authorization.scriptlet' to 'def authorize(a):
    return True
': the required function "authorize" defines arguments ["a"] (expected ["details" "object" "entitlement"])
```

The upstream documentation states `details.Username`, `details.Protocol`, `details.ProjectName` are top-level. **On 7.3 they are not:**

```
Error: Authorization scriptlet execution failed with error: Failed to run: Invalid field "Username"
```

Actual shape, from `dir()`:

```
dir(details)                = ["Certificate", "Chain", "RequestDetails"]
dir(details.RequestDetails) = ["IsAllProjectsRequest", "ProjectName", "Protocol", "Username"]
dir(details.Certificate)    = ["certificate", "description", "name", "projects", "restricted", "type"]
```

`details.Certificate.name` is the trust-store name (`spike-attestor-ro`), which is what makes a readable policy possible; `details.RequestDetails.Username` is the certificate fingerprint.

Object formats and the entitlement for every operation are tabulated in [`authz-vocabulary.txt`](authz-vocabulary.txt).

### Safety of the change

`authorization.scriptlet` is a **global** server option, so the blast radius was established before enabling it. Incus 7.3 routes clients per authentication class, with fixed built-in routing when unset: `unix=allow`, `tls=allow`, `tls-restricted=tls`, `oidc=allow`, `default=deny`.

Only `authorization.client.tls-restricted` was changed. The admin certificate is *unrestricted* TLS and keeps `allow`; the unix socket keeps `allow`; `authorization.client.default` was deliberately **never** set, as upstream warns. Admin access was re-verified after every scriptlet change and never interrupted. Baseline config recorded in [`server-config-baseline.txt`](server-config-baseline.txt) before any change.

## Final policy

[`scriptlet-p5.star`](scriptlet-p5.star) — active on the host.

```python
PROJECT = "spike-spiffe"

def authorize(details, object, entitlement):
    cert = details.Certificate
    name = cert.name

    if not cert.restricted:
        return False
    if PROJECT not in cert.projects:
        return False

    instance_prefix = "instance:" + PROJECT + "/"
    handshake = object == "server:incus" and entitlement == "can_view"

    if name == "spike-attestor-ro":
        if handshake:
            return True
        return object.startswith(instance_prefix) and entitlement == "can_view"

    if name == "spike-bootstrap-writer":
        if handshake:
            return True
        return object.startswith(instance_prefix) and entitlement == "can_edit"

    return False
```

`server:incus can_view_sensitive` is asked on every request but is **not** required: it is denied, and instance reads still return the full `config` map including `volatile.uuid`.

## Adversarial matrix

Both identities, run against the final scriptlet via their own isolated `INCUS_CONF`. Full verbatim output: [`matrix2-attestor-ro-scriptlet.txt`](matrix2-attestor-ro-scriptlet.txt), [`matrix2-writer-scriptlet.txt`](matrix2-writer-scriptlet.txt). Driver: [`matrix2.sh`](matrix2.sh).

`ALLOW` / `DENY` below is the authorization outcome. Delete was always tested against a throwaway `spike-authz-victim`, never the probe.

| Case | Operation | `spike-attestor-ro` | `spike-bootstrap-writer` | Denial text |
|---|---|---|---|---|
| A1 | Resolve instance by `volatile.uuid` | **ALLOW** (intended) | DENY (returns `[]`) | filtered-empty, no error |
| A2 | GET single instance record | **ALLOW** (intended) | DENY | `Error: Permission denied` |
| A3 | `incus list` in own project | **ALLOW** | DENY (empty table) | filtered-empty |
| B1 | PATCH set `user.spiffe-bootstrap` | DENY | **ALLOW** (intended) | `Error: Permission denied` |
| B2 | PATCH clear `user.spiffe-bootstrap` | DENY | **ALLOW** (intended) | `Error: Permission denied` |
| C1 | PATCH `volatile.uuid` (spoof anchor) | DENY | **ALLOW — RESIDUAL** | `Error: Permission denied` |
| C2 | PATCH `volatile.uuid.generation` | DENY | **ALLOW — RESIDUAL** | `Error: Permission denied` |
| C3 | PATCH `security.privileged` | DENY | **ALLOW — RESIDUAL** | `Error: Permission denied` |
| C4 | PATCH unrelated `user.evil` | DENY | **ALLOW — RESIDUAL** | `Error: Permission denied` |
| D1 | Create instance | DENY | DENY | `Error: Failed instance creation: Permission denied` |
| D2 | Delete instance (CLI) | DENY | DENY (CLI pre-read blocked) | attestor: `Error: Failed deleting instance ovh:spike-authz-victim in project "spike-spiffe": Permission denied` · writer: `Error: Failed checking instance ovh:spike-authz-victim exists: Permission denied` |
| D3 | Delete instance (raw `DELETE`) | DENY | **ALLOW — RESIDUAL** | `Error: Permission denied` |
| D4 | Stop instance (`PUT …/state`) | DENY | DENY | `Error: Permission denied` |
| D5 | Exec into instance | DENY | DENY | `Error: Permission denied` |
| D6 | Pull file from instance | DENY | DENY | `Error: Permission denied` |
| D7 | Rename instance | DENY | **ALLOW (authorized) — RESIDUAL** | `Error: Permission denied` |
| E1 | GET `spire-server` in `default` | DENY | DENY | `Error: Permission denied` |
| E2 | List instances in `default` | DENY (empty) | DENY (empty) | filtered-empty |
| E3 | List across all projects | own project only | own project only | confinement holds |
| E4 | GET `lab-c2` in `spike-uuid-lab` | DENY | DENY | `Error: Permission denied` |
| E5 | List projects | DENY (`[]`) | DENY (`[]`) | filtered-empty |
| E6 | Create project | DENY | DENY | `Error: Permission denied` |
| F1 | Host resources `/1.0/resources` | DENY | DENY | `Error: Permission denied` |
| F2 | List storage pools | **ALLOW — RESIDUAL** (name `local` only) | **ALLOW — RESIDUAL** | — |
| F3 | Trust store `/1.0/certificates` | DENY (`[]`) | DENY (`[]`) | filtered-empty |
| F4 | Set server config | DENY | DENY | `Error: Permission denied` |
| F5 | Add trust certificate (escalation) | DENY | DENY | `Error: not authorized` |
| F6 | GET `/1.0` server info | **ALLOW — RESIDUAL** (handshake) | **ALLOW — RESIDUAL** | scriptlet body **not** exposed; `config` is `{}` |
| G1 | Edit project config | DENY | DENY | `Error: Permission denied` |
| G2 | List storage volumes | DENY (`[]`) | DENY (`[]`) | filtered-empty |
| G3 | Edit `default` profile | DENY | DENY | `Error: Permission denied` |
| G4 | List images | DENY (`[]`) | DENY (`[]`) | filtered-empty |
| G5 | Read own certificate entry | DENY (`[]`) | DENY (`[]`) | filtered-empty |

Verbatim samples:

```
### CASE: D1 create instance
$ incus create docker:debian:trixie ovh:spike-authz-newvictim --project spike-spiffe -c oci.entrypoint=sleep infinity
Creating ovh:spike-authz-newvictim
Error: Failed instance creation: Permission denied
[exit=1]

### CASE: E1 GET protected instance in default project
$ incus query ovh:/1.0/instances/spire-server?project=default
Error: Permission denied
[exit=1]

### CASE: F1 host resources
$ incus query ovh:/1.0/resources
Error: Permission denied
[exit=1]
```

Writer holding only `can_edit` successfully deleting an instance — the residual that matters most:

```
### CASE: D3 DELETE victim via raw API
$ incus query -X DELETE ovh:/1.0/instances/spike-authz-victim?project=spike-spiffe
{
	"class": "task",
	"description": "Deleting instance",
	...
[exit=0]
```

## Residual permissions

Every permission that could not be removed.

### Shared by both identities (irreducible)

| # | Residual | Why it cannot be removed | Exposure |
|---|---|---|---|
| R1 | `GET /1.0` server info | Client handshake. Denying `server:incus can_view` breaks every request including intended ones ([`minimal-grant-experiment.txt`](minimal-grant-experiment.txt)) | Server name, IncusOS, kernel version, listen addresses, storage driver, server cert fingerprint. Server `config` is `{}` — the scriptlet is **not** leaked |
| R2 | `GET /1.0/storage-pools` | Gated only by the handshake entitlement; no per-pool question is asked for the list | Pool name `local` only. Volume listing is denied |

`/1.0/resources` — host CPU model, RAM, disk serials, NICs — **is** denied under the scriptlet (it was readable under restricted TLS alone).

### `spike-attestor-ro`

**No residual write of any kind.** Every write, lifecycle, state-change, exec and file operation is denied. It can read the full instance record of *any* instance in `spike-spiffe` (by design; only the probe exists). Beyond R1/R2 there is nothing.

### `spike-bootstrap-writer` — the exact grant is impossible

Requested grant: set/clear one config key. Incus 7.3 cannot express it, because the scriptlet is never given the request body.

**Smallest achievable grant:** `instance:spike-spiffe/* can_edit` plus the handshake. That unavoidably carries:

| # | Residual | Impact |
|---|---|---|
| R3 | Write **any** instance config key | Includes `security.privileged`, `limits.*`, and any `user.*` |
| R4 | Write `volatile.uuid` and `volatile.uuid.generation` | **Can forge the identity anchor.** Confirms and extends P6's finding. Observed: probe UUID rewritten to `00000000-0000-0000-0000-0000000000ff` |
| R5 | **Delete** any instance in `spike-spiffe` | No separate delete entitlement exists; DELETE authorizes as `can_edit`. Proven live (case D3) |
| R6 | **Rename** any instance in `spike-spiffe` | Authorization granted; the live attempt then failed on the unrelated runtime rule `Renaming of running instance not allowed`, so a stopped instance would be renamed |

What the writer still **cannot** do: read any instance (A2/A3 denied — it is genuinely write-only), create instances, stop/start, exec, pull files, touch other projects, or change project/profile/server config.

**This is the phase's key negative result.** The bootstrap writer is not a narrowly-scoped credential; it is an instance-mutation credential for the whole project, and it can forge `volatile.uuid`. It must be treated as at least as sensitive as the attestor credential, and must never be issued into the same trust domain as anything that consumes attestor output.

Options considered and rejected for closing R3–R6:

- Per-key grant in the scriptlet — impossible, body not passed.
- OpenFGA — same model granularity (`instance … can_edit`); would not separate config keys either.
- One instance per project so `can_edit` is narrower — reduces blast radius to one instance but still permits R3/R4/R5 on it; does not fix UUID forgery.
- **Recorded alternative:** since `volatile.uuid` is forgeable by any config-writer, do not let a bootstrap writer coexist with the attestor's trust assumptions. Either the bootstrap key is written by the admin credential during provisioning, or the attestor must not treat `volatile.uuid` as unforgeable against a principal holding project config-write. This is a P7/P8 design input, not something authorization can fix.

## Credential recipes

Two independently generated EC P-384 keypairs. **No shared key material** — separate `openssl req` invocations, distinct keys, distinct fingerprints.

| Identity | Subject | SHA-256 fingerprint | Trust store name | Expiry |
|---|---|---|---|---|
| `spike-attestor-ro` | `CN=spike-attestor-ro, O=spike-incusos-spire` | `6E:BA:F5:EB:4C:C9:E0:03:AC:B6:A9:8E:F7:CD:D2:4B:1D:2D:7A:00:EF:59:F5:FB:9B:65:4E:3F:A6:34:DB:80` | `spike-attestor-ro` (`6ebaf5eb4cc9`) | 2026-09-15 |
| `spike-bootstrap-writer` | `CN=spike-bootstrap-writer, O=spike-incusos-spire` | `AF:D4:F6:08:E0:F0:E8:AA:BC:E5:E4:2A:6D:BA:33:CA:7F:F3:B7:6D:EF:AD:3F:0E:28:7F:46:C5:13:6D:9D:84` | `spike-bootstrap-writer` (`afd4f608e0f0`) | 2026-09-15 |

Private keys live only in `$HOME/.spike-incusos-creds/<identity>/conf/client.key`, mode `0600`, directories `0700`, outside every git repository. No key material is reproduced in this repo.

### Recreate a credential (run once per identity)

```bash
CRED=$HOME/.spike-incusos-creds
ID=spike-attestor-ro          # or spike-bootstrap-writer

mkdir -p "$CRED/$ID/conf"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -sha384 \
  -keyout "$CRED/$ID/conf/client.key" -nodes \
  -out "$CRED/$ID/conf/client.crt" -days 30 \
  -subj "/CN=$ID/O=spike-incusos-spire" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=clientAuth"
chmod 0700 "$CRED" "$CRED/$ID" "$CRED/$ID/conf"
chmod 0600 "$CRED/$ID/conf/client.key" "$CRED/$ID/conf/client.crt"

# Register as a project-restricted trust certificate (admin credential).
# NOTE: remote and path are SEPARATE arguments.
incus config trust add-certificate ovh-incusos: "$CRED/$ID/conf/client.crt" \
  --name "$ID" --description "P5 <role>" --restricted --projects spike-spiffe

# Isolated client config so the admin credential is never reused.
INCUS_CONF="$CRED/$ID/conf" incus remote add ovh https://147.135.105.83:8443 \
  --accept-certificate --auth-type tls --project spike-spiffe
```

The server-side policy ([`scriptlet-p5.star`](scriptlet-p5.star)) keys off the trust-store `--name`, so the name must match exactly. Regenerating a certificate does not require editing the scriptlet; renaming does.

### Use

```bash
# Attestor: resolve UUID -> verified metadata (read-only)
INCUS_CONF=$HOME/.spike-incusos-creds/spike-attestor-ro/conf \
  incus query "ovh:/1.0/instances?recursion=1&project=spike-spiffe&filter=config.volatile.uuid%20eq%20<uuid>"

# Bootstrap writer: set / clear the key (write-only; raw PATCH avoids needing read)
INCUS_CONF=$HOME/.spike-incusos-creds/spike-bootstrap-writer/conf \
  incus query -X PATCH "ovh:/1.0/instances/<name>?project=spike-spiffe" \
    -d '{"config":{"user.spiffe-bootstrap":"<token>"}}'
INCUS_CONF=$HOME/.spike-incusos-creds/spike-bootstrap-writer/conf \
  incus query -X PATCH "ovh:/1.0/instances/<name>?project=spike-spiffe" \
    -d '{"config":{"user.spiffe-bootstrap":""}}'
```

### Enable the policy (already applied on the host)

```bash
incus config set ovh-incusos: authorization.scriptlet=- < scriptlet-p5.star
incus config set ovh-incusos: authorization.client.tls-restricted=scriptlet
# Do NOT set authorization.client.default — upstream warns it applies to every
# unset class at once. tls (admin) and unix keep their built-in "allow".
```

## Commands exercised

```bash
# --- mechanism discovery ---
incus auth --help                                  # Error: unknown command "auth" for "incus"
incus query ovh-incusos:/1.0/auth                  # Error: not found
incus query ovh-incusos:/1.0/auth/identities       # Error: not found
incus query ovh-incusos:/1.0/auth/groups           # Error: not found
incus query ovh-incusos:/1.0/auth/permissions      # Error: not found
incus config trust --help
incus config trust add --help
incus config trust add-certificate --help
incus query ovh-incusos:/1.0/metadata/configuration
incus config show ovh-incusos:                     # baseline, before any change

# --- project and probe ---
incus project create ovh-incusos:spike-spiffe
incus project show ovh-incusos:spike-spiffe
incus profile device add ovh-incusos:default root disk pool=local path=/ --project spike-spiffe
incus profile device add ovh-incusos:default eth0 nic network=incusbr0 --project spike-spiffe
incus launch docker:debian:trixie ovh-incusos:spike-authz-probe --project spike-spiffe -c oci.entrypoint="sleep infinity"

# --- required operations ---
incus query 'ovh-incusos:/1.0/instances/spike-authz-probe?project=spike-spiffe'
incus query "ovh-incusos:/1.0/instances?recursion=1&project=spike-spiffe&filter=config.volatile.uuid%20eq%20<uuid>"
incus config set   ovh-incusos:spike-authz-probe user.spiffe-bootstrap=probe-token-abc --project spike-spiffe
incus config get   ovh-incusos:spike-authz-probe user.spiffe-bootstrap --project spike-spiffe
incus config unset ovh-incusos:spike-authz-probe user.spiffe-bootstrap --project spike-spiffe

# --- identities ---
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -sha384 \
  -keyout client.key -nodes -out client.crt -days 30 \
  -subj "/CN=<id>/O=spike-incusos-spire" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=clientAuth"
incus config trust add-certificate ovh-incusos: <crt> --name <id> --restricted --projects spike-spiffe
INCUS_CONF=<dir> incus remote add ovh https://147.135.105.83:8443 --accept-certificate --auth-type tls --project spike-spiffe
INCUS_CONF=<dir> incus remote add docker https://docker.io --protocol=oci --public
incus config trust list ovh-incusos:

# --- scriptlet ---
incus config set ovh-incusos: authorization.scriptlet="# empty"                  # validation probe
printf 'def authorize(a):\n    return True\n' | incus config set ovh-incusos: authorization.scriptlet -
incus config set ovh-incusos: authorization.scriptlet=- < scriptlet-discovery.star
incus config set ovh-incusos: authorization.client.tls-restricted=scriptlet
incus monitor ovh-incusos: --type=logging --pretty                               # harvest object/entitlement
incus config set ovh-incusos: authorization.scriptlet=- < scriptlet-p5.star

# --- adversarial matrices (full drivers committed) ---
./matrix.sh  spike-attestor-ro        # mechanism (b) baseline
./matrix.sh  spike-bootstrap-writer
./matrix2.sh spike-attestor-ro        # final scriptlet
./matrix2.sh spike-bootstrap-writer
```

## Cleanup

| Action | Status |
|---|---|
| `spike-authz-victim` throwaway instances | Deleted (the final one by case D3 itself). Project contains only the probe |
| Probe config damage from adversarial writes (`volatile.uuid`, `volatile.uuid.generation`, `user.evil`, `security.privileged`, `user.spiffe-bootstrap`) | Reverted; UUID and generation restored to `6d1c5ee3-5b2f-4ead-8e54-db985302fbdb`; probe stopped/started to clear `security.privileged`; verified no stray keys |
| Probe stopped by adversarial cases under mechanism (b) | Restarted; RUNNING at phase end |
| `user.evil` on the `spike-spiffe` `default` profile | Unset |
| Discovery scriptlets | Replaced by `scriptlet-p5.star`; `/tmp` copies are throwaway |
| `incus monitor` log follower | Stopped |
| Protected `default` containers and volumes | Never touched; all four verified RUNNING |
| `authorization.client.default` | Never set |
| Private key material | Only under `$HOME/.spike-incusos-creds/`, mode 0600, outside all git repos |

**Deliberately left in place** (all on the teardown inventory):

- Project `spike-spiffe` with `spike-authz-probe` **RUNNING** — required by the task for the orchestrator's cross-check.
- Both trust certificates — the orchestrator will re-run P6 reads as `spike-attestor-ro`.
- `authorization.scriptlet` and `authorization.client.tls-restricted=scriptlet` — **left enabled deliberately.** Without them `spike-attestor-ro` is a full project operator, so the cross-check would not be testing a read-only credential. Admin and unix access are unaffected and were verified after every change.

## Teardown inventory additions

| Item | Identifier | Removal command |
|---|---|---|
| Incus project | `spike-spiffe` | `incus project delete ovh-incusos:spike-spiffe` (delete the probe first) |
| Container | `spike-authz-probe` in `spike-spiffe` | `incus delete ovh-incusos:spike-authz-probe --project spike-spiffe --force` |
| Trust certificate | `spike-attestor-ro` (`6ebaf5eb4cc9`) | `incus config trust remove ovh-incusos: 6ebaf5eb4cc9` |
| Trust certificate | `spike-bootstrap-writer` (`afd4f608e0f0`) | `incus config trust remove ovh-incusos: afd4f608e0f0` |
| Server config | `authorization.client.tls-restricted` | `incus config unset ovh-incusos: authorization.client.tls-restricted` |
| Server config | `authorization.scriptlet` | `incus config unset ovh-incusos: authorization.scriptlet` |
| Credential directory | `$HOME/.spike-incusos-creds/` (both identities, private keys) | `rm -rf $HOME/.spike-incusos-creds` |

Unset the routing key **before** the scriptlet, so restricted certs fall back to the `tls` driver rather than hitting an absent scriptlet. Baseline server config to restore to: [`server-config-baseline.txt`](server-config-baseline.txt) — only the four `core.https_address` / `storage.*` keys.

## Handoff

**For P6:** `spike-attestor-ro` is live and genuinely read-only; the one-call UUID resolution above returns every field P6's schema needs. Confirmed and extended P6's spoofing finding: `volatile.uuid` and `volatile.uuid.generation` are writable by any principal with `can_edit`, and Incus cannot withhold that while still allowing a `user.*` write.

**For P7/P8 — design inputs:**

1. The attestor credential is clean. Read-only, project-confined, no write path, cannot forge anything. Safe to embed in the attestor plugin.
2. The bootstrap-writer credential is **not** narrowly scoped and cannot be made so on Incus 7.3. It carries full instance-config write, delete, and rename within `spike-spiffe`, including `volatile.uuid`. Design accordingly: either keep bootstrap writes on the admin/provisioning path, or accept that a compromised bootstrap writer can forge the identity anchor that the attestor trusts.
3. `volatile.uuid` is only as trustworthy as the set of principals holding project config-write. If the anchor must be unforgeable, it needs a second, non-Incus-mutable binding — a P7/P8 architecture question, not an authorization one.
4. Deploying the scriptlet in production: it is server-global. Route **only** `authorization.client.tls-restricted`, never `authorization.client.default`, and re-implement project confinement inside the scriptlet — Incus stops enforcing the certificate's project list once the class is routed away from `tls`.
5. Upstream authorization docs are stale for 7.3 (`details.Username` etc.). Use [`authz-vocabulary.txt`](authz-vocabulary.txt) as the reference for the real struct shape, object formats, and per-operation entitlements.

## Files

| File | Contents |
|---|---|
| [`server-config-baseline.txt`](server-config-baseline.txt) | Server config before any change |
| [`probe-create.txt`](probe-create.txt) | Project profile provisioning + probe launch |
| [`admin-write-baseline.txt`](admin-write-baseline.txt) | Bootstrap key set/get/unset as admin |
| [`trust-add.txt`](trust-add.txt) | Certificate registration + trust list |
| [`identity-bootstrap.txt`](identity-bootstrap.txt) | Isolated `INCUS_CONF` setup for both identities |
| [`matrix.sh`](matrix.sh) | Mechanism (b) matrix driver |
| [`matrix-attestor-ro-tls.txt`](matrix-attestor-ro-tls.txt) | Attestor under restricted TLS |
| [`matrix-writer-tls.txt`](matrix-writer-tls.txt) | Writer under restricted TLS |
| [`matrix-attestor-ro-lifecycle.txt`](matrix-attestor-ro-lifecycle.txt) | Corrected create/delete test under restricted TLS |
| [`host-surface-detail.txt`](host-surface-detail.txt) | Host/server exposure under restricted TLS |
| [`scriptlet-discovery.star`](scriptlet-discovery.star) | Logging scriptlet used for vocabulary discovery |
| [`authz-vocabulary.txt`](authz-vocabulary.txt) | Live `authorize()` contract, object formats, entitlement per operation |
| [`scriptlet-tighter-rejected.star`](scriptlet-tighter-rejected.star) | Rejected variant without the handshake grant |
| [`minimal-grant-experiment.txt`](minimal-grant-experiment.txt) | Proof that `server:incus can_view` is irreducible |
| [`scriptlet-p5.star`](scriptlet-p5.star) | **Final policy, active on the host** |
| [`matrix2.sh`](matrix2.sh) | Final matrix driver |
| [`matrix2-attestor-ro-scriptlet.txt`](matrix2-attestor-ro-scriptlet.txt) | Attestor under final scriptlet |
| [`matrix2-writer-scriptlet.txt`](matrix2-writer-scriptlet.txt) | Writer under final scriptlet |
| [`probe-restore-1.txt`](probe-restore-1.txt) | First probe restoration |
| [`final-state.txt`](final-state.txt) | Final server config, trust store, project contents, protected containers |

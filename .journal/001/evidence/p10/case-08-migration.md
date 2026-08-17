## Case 8 — Migration

**Verdict:** DEFERRED

**Setup:** Live host `ovh-incusos` (`ns1001912.ip-147-135-105.us`, `https://147.135.105.83:8443`), IncusOS `202608102114`, Incus server `7.3`. Two throwaway projects created for this case, `spike-p10-mig-a` and `spike-p10-mig-b`, each with `features.images=false -c features.profiles=false -c features.networks=false`; one throwaway instance `p10-mig1` from the already-cached OCI image `docker:debian:trixie` (`f005c3b83cc4…20a16`) with `-c oci.entrypoint="sleep infinity"`. Nothing in `spike-spiffe` or `default` was touched.

**Instance-type choice, stated explicitly:** this case used a **container**, not a VM. Justification: the claims under test are about the instance *record* — `volatile.uuid`, `volatile.uuid.generation`, `project`, `created_at` — and P6 measured the full lifecycle matrix twice, once with a container and once with a real `images:debian/13` VM, and recorded "**Container vs VM divergence: none was observed in UUID or generation behavior. Every transition produced the same outcome in both passes**" (P6 `EVIDENCE.md`, §VM pass). The only VM-specific behaviors P6 found (guest-visible DMI `product_uuid`, restore rebooting the guest, `volatile.vsock_id`) are guest-tooling effects, none of which this case exercises. A container also avoids a multi-GB export tarball for the second proxy.

**Action:**

1. Establish that the case is untestable as written: confirm the host is not part of a cluster.
2. **Proxy A — cross-project move.** Record `volatile.uuid` / `volatile.uuid.generation`, run `incus move … --project spike-p10-mig-a --target-project spike-p10-mig-b`, record both again.
3. **Proxy B — stopped export then import.** `incus export` the stopped instance to a tarball, `incus import` it under a new name in the same project, compare the imported instance's identity keys against the original's.
4. Reconcile both proxies against the P6 observation tables.

**Expected:** the plan's text for this row, verbatim: "**Untestable on this single node** — real cluster-member migration deferred; run the closest proxies (project move / stopped export+import) and record UUID/generation effects; mark as an explicit conditional in go/no-go."

**Observed:**

### 1. The host is not clustered — the case cannot be run as written

Transcript: [`case-08-01-not-clustered.txt`](case-08-01-not-clustered.txt). Three independent probes agree, quoted verbatim:

```
$ incus cluster list ovh-incusos:
Error: Server isn't part of a cluster
(exit 1)

$ incus query ovh-incusos:/1.0/cluster
{
	"enabled": false,
	...
	"server_name": ""
}

$ incus query ovh-incusos:/1.0/cluster/members
Error: Server is not clustered
(exit 1)
```

and the server environment block:

```
{
  "server_clustered": false,
  "server_name": "ns1001912.ip-147-135-105.us",
  "server_version": "7.3",
  "os_name": "IncusOS"
}
```

P7 recorded `server_clustered: false`; **it still holds.** There is exactly one member, so there is no second cluster member to migrate to, and `incus move --target <member>` has no valid argument. Every instance reports `location: "none"` throughout this case, matching P6's rejection of `incus:location` as a selector.

### 2. Proxy A — cross-project move

Transcript: [`case-08-02-proxy-a-project-move.txt`](case-08-02-proxy-a-project-move.txt).

A live move is refused; the instance must be stopped first. Verbatim:

```
$ incus move ovh-incusos:p10-mig1 ovh-incusos:p10-mig1 --project spike-p10-mig-a --target-project spike-p10-mig-b
Error: Migration API failure: Instance must be stopped to be moved across projects
(exit 1)
```

After `incus stop`, the move succeeded (exit 0). Before/after:

| Field | Before (project `spike-p10-mig-a`) | After (project `spike-p10-mig-b`) | Changed? |
|---|---|---|---|
| `volatile.uuid` | `88013ade-522b-461c-8617-5e8dee9d0c9e` | `88013ade-522b-461c-8617-5e8dee9d0c9e` | **no** |
| `volatile.uuid.generation` | `88013ade-522b-461c-8617-5e8dee9d0c9e` | `88013ade-522b-461c-8617-5e8dee9d0c9e` | **no** |
| `project` | `spike-p10-mig-a` | `spike-p10-mig-b` | **yes** |
| `name` | `p10-mig1` | `p10-mig1` | no |
| `type` | `container` | `container` | no |
| `location` | `none` | `none` | no |
| `created_at` | `2026-08-17T17:00:42.256298558Z` | `2026-08-17T17:01:13.084922021Z` | **yes — reset to the move time** |
| `volatile.base_image` | `f005c3b83cc4…20a16` | `f005c3b83cc4…20a16` | no |

Starting the instance in the new project changed neither identity key. The record vanishes from the old project (`Error: Failed to fetch instance "p10-mig1" in project "spike-p10-mig-a": Instance not found`), and the UUID filter scoped to the old project returns `{"matches": 0}` while the all-projects filter returns exactly one record, now in `spike-p10-mig-b`.

Selector-shaped, this is the whole result:

```
before: incus:uuid:88013ade-… incus:generation:88013ade-… incus:project:spike-p10-mig-a incus:name:p10-mig1
after : incus:uuid:88013ade-… incus:generation:88013ade-… incus:project:spike-p10-mig-b incus:name:p10-mig1
```

**Both identity keys survive relocation; only the `incus:project` selector changes.** A registration entry pinned on `incus:uuid` alone keeps matching after a project move; an entry that also pins `incus:project` stops matching, and fails closed.

### 3. Proxy B — stopped export then import

Transcript: [`case-08-03-proxy-b-export-import.txt`](case-08-03-proxy-b-export-import.txt) (contains the raw `incus export`/`incus import` progress output).

The backup tarball carries the identity keys verbatim in `backup/index.yaml`:

```
32:      volatile.uuid: 88013ade-522b-461c-8617-5e8dee9d0c9e
33:      volatile.uuid.generation: 88013ade-522b-461c-8617-5e8dee9d0c9e
```

`incus import … p10-mig1-imported` (exit 0) produced a second, independent instance in the same project whose record is identical in every identity field:

| Field | Original `p10-mig1` | Imported `p10-mig1-imported` |
|---|---|---|
| `volatile.uuid` | `88013ade-522b-461c-8617-5e8dee9d0c9e` | `88013ade-522b-461c-8617-5e8dee9d0c9e` |
| `volatile.uuid.generation` | `88013ade-522b-461c-8617-5e8dee9d0c9e` | `88013ade-522b-461c-8617-5e8dee9d0c9e` |
| `created_at` | `2026-08-17T17:01:13.084922021Z` | `2026-08-17T17:01:13.084922021Z` |
| `project` / `type` | `spike-p10-mig-b` / `container` | `spike-p10-mig-b` / `container` |
| `name` | `p10-mig1` | `p10-mig1-imported` |

The attestor's own lookup surface then returns **two** records for one UUID:

```
$ incus list ovh-incusos: --project spike-p10-mig-b config.volatile.uuid=88013ade-522b-461c-8617-5e8dee9d0c9e --format csv -c ns
p10-mig1,STOPPED
p10-mig1-imported,STOPPED
```

Incus does refuse *something* about the duplicate, but not the identity. The first start attempt of either instance failed on NIC uniqueness, verbatim:

```
Error: Failed start validation for device "eth0": MAC address "10:66:6a:50:8b:63" already defined on another NIC
```

That guard is trivially cleared — `incus config unset … volatile.eth0.hwaddr` on the imported copy (exit 0) — after which **both instances started and ran concurrently while reporting the same `volatile.uuid` and the same `volatile.uuid.generation`**, and the all-projects UUID filter returned both as `Running`. So Incus enforces MAC-address uniqueness at start validation and does **not** enforce `volatile.uuid` uniqueness at any point.

### 4. Reconciliation against the P6 observation tables

| P6 row / claim (`p6/EVIDENCE.md`, `p6/REFERENCE_SCHEMA.md`) | This case's result |
|---|---|
| `REFERENCE_SCHEMA.md` §2, `incus:project` row: "Constant for the instance's life on this deployment (project move not exercised — see §6)" | **Extended and corrected.** A project move *is* available on this deployment, needs only a stop, and does change `incus:project` while both identity keys hold. `incus:project` is a mutable-by-supported-operation selector, not a life-constant one. |
| `REFERENCE_SCHEMA.md` §6 open question: "Does moving an instance between projects preserve `volatile.uuid`? … Owner: P10 (owns the migration proxies)" | **Answered: yes** — and `volatile.uuid.generation` is preserved too, which the question did not ask. |
| `EVIDENCE.md` §Prominent qualification: "uniqueness of `volatile.uuid` is **not enforced by Incus**; it is a generation-time convention" — demonstrated in P6 by deliberate `incus config set` tampering | **Confirmed and materially extended.** P6 needed a principal with instance-config write to forge a duplicate. Proxy B produced a live duplicate through `incus export` + `incus import` alone — a first-class backup/restore workflow, no `volatile.*` write, no tampering, no privileged trick. The duplicate-UUID situation is therefore reachable by ordinary operations, not only by an attacker. |
| `EVIDENCE.md` T5b/T5d/V4b: "`incus copy` … Yes, always" regenerates both `volatile.uuid` and `volatile.uuid.generation` | **Contrasted, not contradicted.** `incus copy` and `incus export`+`incus import` both yield a second instance from one source, but they behave in opposite ways: copy re-randomizes both keys, import replays both verbatim. P6's clone row is confirmed; import is a distinct path P6 never exercised. |
| `EVIDENCE.md` §Candidate fallback anchors, `created_at` row: "Server-owned, survived rename …. Useful as a **corroborating** tiebreaker in a duplicate-UUID situation" | **Contradicted in both directions.** In Proxy B the duplicate's `created_at` is byte-identical (`2026-08-17T17:01:13.084922021Z`), so it does not break the exact tie it was proposed for. In Proxy A `created_at` was *reset* by the move, so it is not stable across relocation either. `created_at` should be dropped as a tiebreaker. |
| `REFERENCE_SCHEMA.md` §3 rule: multi-match on a UUID is "a hard attestation failure, never 'pick one'" | **Confirmed as load-bearing.** Proxy B is the concrete non-adversarial way that rule gets exercised; without it, an attestor would have silently picked one of two live instances. |
| `REFERENCE_SCHEMA.md` §2 rejected selector `incus:location`: "`location` is `none` for every instance on this non-clustered host … Zero information" | **Confirmed unchanged.** `location=none` on every read in this case, before and after both proxies. |

**Cleanup:** Transcript [`case-08-04-cleanup.txt`](case-08-04-cleanup.txt).

- `incus delete ovh-incusos:p10-mig1 ovh-incusos:p10-mig1-imported --force --project spike-p10-mig-b` (exit 0); `incus list --project spike-p10-mig-b/-a --format csv` returned empty for both projects.
- `incus project delete ovh-incusos:spike-p10-mig-a` → `Project ovh-incusos:spike-p10-mig-a deleted`; same for `spike-p10-mig-b`. `incus project list --format csv -c n` now returns only `default (current)` and `spike-spiffe`.
- Local tarball removed: `rm -f /tmp/p10-mig1.tar.gz` then `ls: cannot access '/tmp/p10-mig1.tar.gz': No such file or directory`.
- The proxy UUID resolves nowhere: the all-projects filter for `88013ade-522b-461c-8617-5e8dee9d0c9e` returns `0`.
- No snapshot was created in this case; no image was pulled (the OCI image was already cached); storage volume listing after cleanup shows only the pre-existing image and container volumes ([`final-state.txt`](final-state.txt)).

### Architecture finding `P10-ARCH-001` — current adoption is NO-GO

**Finding:** A supported stopped export/import replayed `volatile.uuid`,
`volatile.uuid.generation`, and `created_at`. After the imported instance's duplicate NIC MAC was
cleared, the source and imported instances ran concurrently with identical identity anchors. This
makes current architecture adoption **NO-GO independently of the deferred cluster-member
migration result**. Reconsider adoption only after either import re-keys or prevents duplicate
anchors, or an authoritative global lookup is verified to return exactly one match and lifecycle
reconciliation is verified and explicitly accepted.

The multi-match hard failure prevents silent instance selection in the duplicate observed on this
single node. It also converts a supported, ordinary lifecycle operation into identity-issuance
unavailability while the duplicate exists. Lookup behavior across multiple cluster members remains
untested.

### Deferred cluster-member migration boundary

The Case 8 verdict remains **DEFERRED** for real cluster-member migration. Adoption also requires a
real migration to preserve `volatile.uuid`; otherwise UUID-anchored registration entries break on
relocation. The test must establish whether a cross-member move changes
`volatile.uuid.generation` and whether UUID lookup is authoritative and globally single-match
across members. The single-node project-move and export/import proxies cannot establish those
cluster-specific properties.

Two additional facts were observed: `incus:project` is not stable under a supported operator
action, so an entry that pins `incus:project` alongside `incus:uuid` fails closed after a project
move and must be reissued deliberately; and `created_at` cannot break a duplicate-UUID tie because
import reproduces it byte-for-byte while project move resets it.

**Secret scan:** [`secret-scan.txt`](secret-scan.txt) — nine Appendix D patterns ([`secret-scan-patterns.txt`](secret-scan-patterns.txt)) over all 15 files this unit wrote: `real-scan exit=0`, with a positive control that made all nine fire on a planted file, plus live `grep -F` comparisons against the actual operator bearer token and the host encryption/pool recovery keys (both clean), plus a clean self-scan of the report.

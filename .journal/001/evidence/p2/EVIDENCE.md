# P2 Evidence — SPIRE Server Placement and Configuration

**Captured:** 2026-08-16 15:10 PDT
**Host:** `ovh-incusos` (`147.135.105.83:8443`), IncusOS `202608102114`, Incus `7.3`
**Decision:** **PASS. Server healthy across container restart and host reboot; both `tpm_devid` CA bundles proven loaded. Together with P1 this unlocks P3.**

## Scope

P2 deployed the spike SPIRE Server as an Incus OCI application container on the OVH host, configured the `tpm_devid` node attestor with the P1 spike DevID root and the P0 Nuvoton endorsement root, and pre-configured the `x509pop` node attestor in `spiffe` mode for later use in P9.

The server runs on the same host it will attest. That is a deliberate spike convenience and **not** an architecture claim. Production topology must separate the server from the attested node; this is recorded here so the later architecture document does not inherit the shortcut.

## Acceptance result

| Criterion | Result | Evidence |
|---|---|---|
| Server healthy | PASS | `spire-server healthcheck` → `Server is healthy.`; `/live` and `/ready` both HTTP 200. |
| Healthy across container restart | PASS | After `incus restart`: healthy, same X.509 authority ID `bb360028cd05a378d3ed0ef4fac03f6fb97d59d8`. |
| Healthy across host reboot | PASS | After `incus admin os system reboot --force`: container auto-restored, healthy, same authority ID. |
| Config loads both CA bundles | PASS | `validate` succeeds with real paths and fails with the exact per-bundle load error when either path is broken. |
| Empty agent list | PASS | `agent list` → `No attested agents found`; `entry count` → `0`. |

## Trust domain and identity plane

| Property | Value |
|---|---|
| Trust domain | `spike.incus.internal` (spike-only, arbitrary) |
| Server SPIFFE ID | `spiffe://spike.incus.internal/spire/server` |
| X.509 authority ID | `bb360028cd05a378d3ed0ef4fac03f6fb97d59d8` |
| JWT authority ID | `jRTMx4I0fHSvXeEWWcJwhsthNdfUJ4sk` |
| Root CA self-signed | yes, no upstream authority |
| Trust bundle certificates | 1 |
| Bundle root subject | `C=US, O=SPIFFE, serialNumber=129944772266556437062337838904092526589` |
| Bundle root SHA-256 | `493bac43bfeb4005fb481606390ac1a77d208f0d0a0561abdd1735efd62bd6c2` |
| CA TTL | `24h` (short on purpose, keeps rotation observable) |
| Default X.509 SVID TTL | `1h` |
| Default JWT SVID TTL | `5m` |

Captured bundle: [`server-trust-bundle.pem.txt`](server-trust-bundle.pem.txt).

The 24-hour CA TTL means the authority will rotate during a multi-day spike. Later phases should expect a `Prepared X.509 authority` to appear and should record the rotation rather than treat it as a fault.

## Image pinning

| Reference | Digest |
|---|---|
| `ghcr.io/spiffe/spire-server:1.15.2` multi-arch index | `sha256:aa74ef1be86bc8e0684007d84a4d9859d294384d842c30425048d73429f3216e` |
| `linux/amd64` manifest (the one in use) | `sha256:410c624a2f2311c23ecc96c24abd854213333f57ccf4fd1c8d3e30b3dbf007bb` |
| `linux/arm64` manifest (Mac-lab equivalent, unused here) | `sha256:8e96e7037b705e6d489b7e2d025403c87e076f7b40df8e111ba9ac53908bfa90` |
| Incus-side image fingerprint | `cc908044b88b0f11437c04db7865851111fa620afb395669799b6cfa25359f4e` |
| Image created | 2026-07-09T19:25:42Z |

Upstream image config, resolved with `skopeo inspect --config --override-os linux --override-arch amd64`:

- Entrypoint: `/opt/spire/bin/spire-server run`
- User: `1000:1000`
- WorkingDir: `/opt/spire`
- No declared volumes, no labels

**Finding worth carrying into the architecture:** Incus records the OCI *tag*, not the digest, in `image.id`, and its own content fingerprint is unrelated to the registry digest. Digest pinning therefore has to be enforced outside Incus — resolve the digest with `skopeo`, record it, and re-verify. Incus alone gives no tag-immutability guarantee.

**Second finding:** the upstream SPIRE images are distroless. `incus exec <ct> -- ls` fails with `Command not found`. Every in-container action must invoke an absolute binary path, and file staging must use `incus file push`/`pull`, which work through the Incus API and need no shell. This shaped the whole verification approach below and will shape P3 too.

## Topology introduced

| Object | Type | Purpose | Retained |
|---|---|---|---|
| `spike-spire-server-state` | Incus custom volume on `local`, `security.shifted=true` | `/spike/conf` and `/spike/data`: config, sqlite datastore, CA keys | Yes, until P11 |
| `spire-server` | Incus OCI application container | The spike SPIRE Server | Yes, until P11 |
| `spike-probe` | Incus OCI application container (Debian + curl/jq/openssl) | Network probe on `incusbr0` for HTTP checks against distroless services | Yes, utility for P3–P10 |
| `spike-p2-stage` | Incus OCI application container | Staged config and public CA bundles onto the server volume | No, deleted after staging |

Instance configuration snapshot: [`spire-server-instance-config.yaml.txt`](spire-server-instance-config.yaml.txt).

Notable instance facts for later phases:

- `oci.entrypoint` override: `/opt/spire/bin/spire-server run -config /spike/conf/server.conf`
- `oci.uid` / `oci.gid`: `1000`
- `volatile.idmap.current`: uid and gid maps of host `1000000` + 1000000000 range, so in-container uid 1000 is host uid 1001000
- `volatile.uuid`: `089b0067-0c97-443e-8f42-c19776761f28`, and `volatile.uuid.generation` currently equal to it
- Network: `incusbr0` NAT bridge, address `10.55.156.67`, host veth `vetheea7e3fc`

That `volatile.uuid` / `volatile.uuid.generation` pair is exactly the authoritative Incus state the custom workload attestor will consume in P5–P7. P2 confirms both keys are present and equal on a fresh container, which is the baseline the P7 generation-change tests will diff against.

`security.shifted=true` was set on the server volume so the same volume can be mounted by containers with different idmaps without an ownership rewrite. The staging container wrote the files as root and then `chown -R 1000:1000`, matching the image's runtime user.

Volume inventory snapshot: [`host-volumes.json.txt`](host-volumes.json.txt). Image inventory: [`host-images.json.txt`](host-images.json.txt).

## Configuration

Full file: [`server.conf.txt`](server.conf.txt). It contains no secrets; the server's private keys live only in `/spike/data/keys.json` on the encrypted volume.

Plugin decisions:

| Plugin | Setting | Rationale |
|---|---|---|
| `DataStore "sql"` | sqlite3 at `/spike/data/datastore.sqlite3` | Spike-scale datastore on the encrypted volume; survives restart and reboot. |
| `KeyManager "disk"` | `/spike/data/keys.json` | Persists the server CA across restarts. A memory key manager would have produced a new authority on every restart and invalidated the persistence test. |
| `NodeAttestor "tpm_devid"` | `devid_ca_path` = spike root CA, `endorsement_ca_path` = Nuvoton TPM Root CA 1110 | The host identity path under test in P3. |
| `NodeAttestor "x509pop"` | `mode = "spiffe"` only | Guest identity path for P9. In `spiffe` mode the plugin validates against the server's own trust bundle, so no `ca_bundle_path` is needed. |
| `health_checks` | listener on `0.0.0.0:8080`, `/live`, `/ready` | Externally observable health for a distroless container. |

`x509pop` defaults were deliberately left untouched, as the plan requires:

- `svid_prefix` = `/spire-exchange`
- `agent_path_template` = `{{ .PluginName }}/{{ .SVIDPathTrimmed }}`

So a guest presenting `spiffe://spike.incus.internal/spire-exchange/<name>` will be exchanged for `spiffe://spike.incus.internal/spire/agent/x509pop/<name>`. P9 and P10 must respect that prefix or attestation is rejected.

`bind_address = "0.0.0.0"` is scoped by the NAT bridge; the server API is not reachable from outside the host. Confirmed reachable from the probe container at `10.55.156.67:8081`.

## CA bundles installed

Both bundles were staged onto the server volume and then read back **out of the running server container** with `incus file pull`, so these are the exact bytes the server loaded:

| Purpose | Config key | Subject | SHA-256 |
|---|---|---|---|
| DevID trust root (P1) | `devid_ca_path` | `O=incusos-spire spike, CN=spike root CA` | `b057b3f2023413fdec184c6262e1de4d760d0943ffd677762adfb1a7510db1eb` |
| Endorsement trust root (P0) | `endorsement_ca_path` | `CN=Nuvoton TPM Root CA 1110 + O=Nuvoton Technology Corporation + C=TW` | `2782e51a95e86d9557fe4204316cf805bd6f5898f81f9732e944d742bcdc5f54` |

The endorsement root was re-downloaded from Nuvoton during staging and its fingerprint was compared against the P0 baseline programmatically; the staging step was written to fail closed on mismatch:

```text
endorsement CA fingerprint: 2782e51a95e86d9557fe4204316cf805bd6f5898f81f9732e944d742bcdc5f54
endorsement CA matches P0 baseline
```

Note the intentional split: the server holds only the spike **root** CA, not the DevID issuing CA. The agent supplies the issuing CA as an intermediate inside `devid.pem`, which is what the server's leaf-plus-intermediates verification expects. P3 will exercise that path for real.

## Startup evidence

Full log: [`spire-server-startup.log.txt`](spire-server-startup.log.txt). Key lines from first boot:

```text
INFO Configured                     admin_ids="[]" data_dir=/spike/data launch_log_level=debug version=1.15.2
INFO Initializing new database       subsystem_name=sql
INFO Connected to SQL database       type=sqlite3 version=3.53.2
INFO Plugin loaded                   plugin_name=disk plugin_type=KeyManager
INFO Plugin loaded                   plugin_name=tpm_devid plugin_type=NodeAttestor
INFO Plugin loaded                   plugin_name=x509pop plugin_type=NodeAttestor
INFO X509 CA activated               local_authority_id=bb360028cd05a378d3ed0ef4fac03f6fb97d59d8 self_signed=true slot=A
INFO JWT key activated               local_authority_id=jRTMx4I0fHSvXeEWWcJwhsthNdfUJ4sk slot=A
DEBU Signed X509 SVID                spiffe_id="spiffe://spike.incus.internal/spire/server"
INFO Starting Server APIs            address="[::]:8081" network=tcp
INFO Starting Server APIs            address=/tmp/spire-server/private/api.sock network=unix
INFO Serving health checks           address="0.0.0.0:8080"
```

One operational note: the server logged `Current umask 0022 is too permissive; setting umask 0027` and corrected itself.

The private API socket lives at `/tmp/spire-server/private/api.sock` **inside** the container, so every CLI call in this phase passed `-socketPath /tmp/spire-server/private/api.sock`. For P3 the agent needs the server's TCP address instead, `10.55.156.67:8081`.

## Health and state checks

```text
$ spire-server healthcheck -socketPath /tmp/spire-server/private/api.sock
Server is healthy.

$ spire-server agent list -socketPath ...
No attested agents found

$ spire-server entry count -socketPath ...
0 registration entries

$ spire-server localauthority x509 show -socketPath ...
Active X.509 authority:
  Authority ID: bb360028cd05a378d3ed0ef4fac03f6fb97d59d8
  Expires at: 2026-08-17 22:04:03 +0000 UTC
  Upstream authority ID: No upstream authority
Prepared X.509 authority:
  No prepared X.509 authority found
```

HTTP health probed from `spike-probe` over `incusbr0`:

```text
GET /live  -> 200 {"catalog.datastore":{},"server":{},"server.ca":{},"server.ca.rotator":{}}
GET /ready -> 200 {"catalog.datastore":{},"server":{},"server.ca":{},"server.ca.rotator":{}}
TCP 10.55.156.67:8081 reachable
```

The four reported health subsystems — `catalog.datastore`, `server`, `server.ca`, `server.ca.rotator` — are useful as the readiness contract for any later production runbook.

## Negative controls

These prove the CA bundle paths are genuinely loaded and parsed, not merely accepted as strings. Each used a copy of the real config with one path broken, validated inside the running container, then discarded.

Broken `devid_ca_path`:

```text
SPIRE server configuration file is invalid.
Validation errors:
	NodeAttestor "tpm_devid":
		unable to load DevID trust bundle: open /spike/conf/does-not-exist.pem: no such file or directory
```

Broken `endorsement_ca_path`:

```text
SPIRE server configuration file is invalid.
Validation errors:
	NodeAttestor "tpm_devid":
		unable to load endorsement trust bundle: open /spike/conf/no-endorsement.pem: no such file or directory
```

Real config, for contrast:

```text
SPIRE server configuration file is valid.
```

`spire-server validate` reaches plugin configuration, so it is a cheap pre-flight for every later config change in this spike. Both negative config files remain on the volume as `/spike/conf/negative-badca.conf` and `/spike/conf/negative-badek.conf` for reuse; neither is referenced by the running server.

## Durability results

### Container restart

```text
$ incus restart ovh-incusos:spire-server
INFO Journal loaded            jwt_keys=1 x509_cas=1
INFO X509 CA activated         local_authority_id=bb360028cd05a378d3ed0ef4fac03f6fb97d59d8 slot=A
INFO Serving health checks     address="0.0.0.0:8080"
Server is healthy.
No attested agents found
```

The authority ID is unchanged, so the disk key manager plus sqlite datastore genuinely persisted the CA. `Journal loaded jwt_keys=1 x509_cas=1` replaces the first-boot `x509_cas=0`.

### Host reboot

After `incus admin os system reboot ovh-incusos: --force` and roughly 95 seconds:

- `spire-server` and `spike-probe` both returned to `RUNNING` with their previous addresses, without intervention.
- `spire-server healthcheck` → `Server is healthy.`
- Authority ID still `bb360028cd05a378d3ed0ef4fac03f6fb97d59d8`.
- Agent list still empty.
- Host invariant held: `{"tpm_status":"ok","trusted":true,"volumes":["unlocked (TPM)","unlocked (TPM)"],"secure_boot":true}`.

Incus restored instance power state automatically. No autostart configuration was needed, which is a useful datapoint: `volatile.last_state.power: RUNNING` drove recovery.

## Commands exercised

```text
skopeo inspect --override-os linux --override-arch amd64 docker://ghcr.io/spiffe/spire-server:1.15.2
skopeo inspect --config --override-os linux --override-arch amd64 docker://ghcr.io/spiffe/spire-server:1.15.2
skopeo inspect --raw docker://ghcr.io/spiffe/spire-server:1.15.2

incus storage volume create ovh-incusos:local spike-spire-server-state security.shifted=true
incus init docker:debian:trixie ovh-incusos:spike-p2-stage -c 'oci.entrypoint=sleep infinity'
incus config device add ovh-incusos:spike-p2-stage ca disk pool=local source=spike-ca-state path=/ca
incus config device add ovh-incusos:spike-p2-stage srvstate disk pool=local source=spike-spire-server-state path=/srv-state
incus file push /tmp/spike-server.conf ovh-incusos:spike-p2-stage/srv-state/conf/server.conf
incus delete ovh-incusos:spike-p2-stage --force

incus init ghcr:spiffe/spire-server:1.15.2 ovh-incusos:spire-server \
  -c 'oci.entrypoint=/opt/spire/bin/spire-server run -config /spike/conf/server.conf'
incus config device add ovh-incusos:spire-server state disk pool=local source=spike-spire-server-state path=/spike
incus start ovh-incusos:spire-server
incus restart ovh-incusos:spire-server
incus admin os system reboot ovh-incusos: --force

incus exec ovh-incusos:spire-server -- /opt/spire/bin/spire-server healthcheck -socketPath /tmp/spire-server/private/api.sock
incus exec ovh-incusos:spire-server -- /opt/spire/bin/spire-server agent list -socketPath ...
incus exec ovh-incusos:spire-server -- /opt/spire/bin/spire-server entry count -socketPath ...
incus exec ovh-incusos:spire-server -- /opt/spire/bin/spire-server bundle show -socketPath ...
incus exec ovh-incusos:spire-server -- /opt/spire/bin/spire-server localauthority x509 show -socketPath ...
incus exec ovh-incusos:spire-server -- /opt/spire/bin/spire-server validate -config /spike/conf/server.conf
incus file pull ovh-incusos:spire-server/spike/conf/devid-ca.pem /tmp/p2-devid-ca.pem
```

## Cleanup

- Deleted the staging container `spike-p2-stage`.
- Retained `spire-server`, its volume, and `spike-probe`; all are needed by later phases and are on the teardown inventory.
- No TPM interaction occurred in this phase; the server does not touch `/dev/tpmrm0`.

## Teardown inventory additions

| Class | Object | Removal |
|---|---|---|
| 4 | `spire-server` container | P11 |
| 4 | Incus volume `local/spike-spire-server-state` | P11 |
| 5 | `spike-probe` utility container | P11 |
| 5 | Host images `cc908044…` (spire-server) and `f005c3b8…` (debian trixie) | P11 |

## Handoff to P3

Agent-side inputs now fixed:

```hcl
# agent.conf excerpt
agent {
    server_address = "10.55.156.67"
    server_port    = "8081"
    trust_domain   = "spike.incus.internal"
}

NodeAttestor "tpm_devid" {
    plugin_data {
        tpm_device_path = "/dev/tpmrm0"
        devid_cert_path = "/spike/devid.pem"
        devid_priv_path = "/spike/devid.priv.blob"
        devid_pub_path  = "/spike/devid.pub.blob"
    }
}
```

Expected node SPIFFE ID form: `spiffe://spike.incus.internal/spire/agent/tpm_devid/<sha1-of-devid-leaf-DER>`.

Expected selectors, from the P1 certificate:

- `tpm_devid:subject:cn:spike-host-devid`
- `tpm_devid:issuer:cn:spike DevID issuing CA`
- `tpm_devid:fingerprint:<sha1 of the issuing CA cert>` — the doc states the fingerprint selector covers each cert in the PoP chain **excluding the leaf**, so expect the issuing CA, not the DevID leaf.

Two P3 prerequisites uncovered here that the plan did not anticipate:

1. **File ownership.** The P1 blob triplet on `spike-spire-agent-state` is `root:root` with `devid.priv.blob` and `devid.pub.blob` at mode `0600`. The agent image runs as uid 1000. P3 must either chown that volume to `1000:1000` or relax the modes, and should set `security.shifted=true` on it as was done for the server volume.
2. **No shell in the agent image.** Expect the same distroless constraint: absolute binary paths for `incus exec`, `incus file push` for config, and the `spike-probe` container for any HTTP checks.

Also unresolved and worth watching in P3: the server's trust bundle currently has exactly one certificate and a 24-hour CA TTL, so an authority rotation is likely mid-spike. Record it when it happens instead of debugging it.

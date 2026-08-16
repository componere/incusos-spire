# P1 Evidence — Spike PKI and TPM-Resident LDevID Provisioning

**Captured:** 2026-08-16 14:50 PDT
**Host:** `ovh-incusos` (`147.135.105.83:8443`), IncusOS `202608102114`, Incus `7.3`
**Decision:** **PASS. H2 confirmed, H4 confirmed (zero persistent TPM footprint). P3 unblocked once P2 is up.**

## Scope

P1 provisioned a TPM-resident DevID (LDevID) signing key on the host's physical Nuvoton TPM and issued its certificate from a disposable two-tier spike CA. This was the first phase permitted to run authorized TPM commands, unlocked by G0.

TPM commands used: `CreatePrimary` (owner and endorsement hierarchies, transient only), `Create`, `Load`, `Hash`, `Sign`, `ReadPublic`, `NV_Read`, `FlushContext`, and capability reads. No `tpm2_clear`, no hierarchy or auth mutation, no `evictcontrol`, and no NV define or write.

## Acceptance result

| Criterion | Result | Evidence |
|---|---|---|
| Valid LDevID chain to the spike DevID CA | PASS | `openssl verify -CAfile spike-root-ca.pem -untrusted spike-devid-ca.pem /state/devid.pem` → `OK`. |
| Blob triplet present on the spike volume | PASS | `devid.pem`, `devid.pub.blob` (280 B), `devid.priv.blob` (190 B) on `spike-spire-agent-state`. |
| TPM diff shows only approved objects | PASS (**none created**) | Persistent handles, NV indices, NV counters, and hierarchy flags identical to the P0 baseline. |
| Post-reboot invariant holds | PASS | After a full host reboot: `tpm_status=ok`, fully trusted state, root and swap `unlocked (TPM)`, all four Secure Boot fingerprints unchanged. |
| Blobs still load after reboot | PASS | Self-check reloaded the blobs under a freshly recreated SRK and signed a nonce successfully. |

## Hypothesis verdicts

**H2 — a TPM-resident LDevID consumable by the SPIRE agent plugin: CONFIRMED.**
The blob pair is byte-compatible with SPIRE 1.15.2's `tpm_devid` agent plugin, which reads `devid_pub_path` and `devid_priv_path` verbatim and passes them to `tpm2.DecodePublic` and `tpm2.Load` under a runtime-recreated SRK.

**H4 — minimal or zero persistent TPM footprint: CONFIRMED, zero.**
The DevID key is a child of the H-1 storage root key, which is recreated on demand from the owner hierarchy seed. Nothing was persisted to a TPM handle and nothing was written to NV. No handle from the P0 allocation table was consumed, so the P11 teardown has no TPM object to remove.

## Tooling decision

The plan's primary candidate was the HPE `devid-provisioning-tool`. It was rejected: its last commit is `2021-08-02`, roughly five years stale, which fails the repository's dependency rule against obviously abandoned projects (AGENTS.md L1). Its compatibility with SPIRE 1.15.2 blob loading was flagged as an assumption in the plan and remains unverified.

The plan's documented fallback was used instead: a small throwaway Go program built against the exact library SPIRE 1.15.2 depends on, `github.com/google/go-tpm v0.9.8`, with the SRK template copied from SPIRE's own `tpmutil.SRKTemplateHighRSA`.

Source transcripts: [`spike-devid.go.txt`](spike-devid.go.txt), [`spike-devid.go.mod.txt`](spike-devid.go.mod.txt), [`spike-ca-init.sh.txt`](spike-ca-init.sh.txt).

`tpm2-tools` was deliberately **not** used to create the DevID blobs. Its `tpm2_create -u/-r` output is size-prefixed `TPM2B` data, while SPIRE reads the raw `TPMT_PUBLIC` and `TPM2B_PRIVATE` contents. That mismatch would have produced blobs the agent cannot load.

## SPIRE compatibility facts established from source

Read from `spiffe/spire` at tag `v1.15.2`:

- `pkg/agent/plugin/nodeattestor/tpmdevid/devid.go` reads the configured blob files with `os.ReadFile` and passes the bytes through unchanged.
- `pkg/agent/plugin/nodeattestor/tpmdevid/tpmutil/session.go` recreates the parent with `CreatePrimaryEx(HandleOwner, PCRSelection{}, ownerHierarchyPassword, <fresh random auth>, SRKTemplateHighRSA())`, then calls `tpm2.Load(srk, <same random auth>, pub, priv)`.
- The DevID public area must have the `sign` attribute and a non-null signing hash, or `loadKey` rejects it.
- `SolveDevIDChallenge` signs the server nonce via `tpm2.Hash(..., HandlePlatform)` followed by `tpm2.Sign` with the returned validation ticket.
- `GetEKCert` reads NV index `0x01C00002` and trims trailing bytes after the DER certificate.
- The server (`pkg/server/plugin/nodeattestor/tpmdevid/devid.go`) treats `DevIDCert[0]` as the leaf and `DevIDCert[1:]` as intermediates, verifying against the `devid_ca_path` root pool, and verifies the EK certificate directly against the `endorsement_ca_path` pool.

The fresh-random-auth detail drove the self-check design: the blobs must load under an SRK created with an auth value different from the provisioning-time one. Primary key derivation depends on the hierarchy seed and template, not on the auth value.

## Topology introduced

| Object | Type | Purpose | Retained after P1 |
|---|---|---|---|
| `spike-spire-agent-state` | Incus custom volume, pool `local` | DevID blob triplet and later agent data dir | Yes — P3 consumes it |
| `spike-ca-state` | Incus custom volume, pool `local` | Disposable spike CA keys and certificates | Yes — P3 negative case (b) needs the issuing CA |
| `spike-devid-enroll` | Incus OCI application container | Enrollment workspace | No — deleted at P1 close |

Both volumes live on the `local` ZFS pool, which IncusOS encrypts with a pool key sealed to the same TPM, satisfying the plan's encrypted-spike-volume requirement.

Enrollment environment: `docker:debian:trixie`, `tpm2-tools 5.7-1`, `openssl 3.5.6-1~deb13u2`, `golang-go 2:1.24~2`, TPM passed through as `unix-char` `source=/dev/tpmrm0 path=/dev/tpmrm0`.

## Step 1 — Endorsement key confirmation (H1 discovery completion)

A transient RSA EK was created with `tpm2_createek -G rsa -c ek.ctx`, its public key exported, and compared with the public key inside the manufacturer EK certificate at NV `0x01C00002`:

```text
live EK sha256: b583a3ecd334e0d80edc88c6015de614756dea4cad1ab55c9aec763674d34197
cert EK sha256: b583a3ecd334e0d80edc88c6015de614756dea4cad1ab55c9aec763674d34197
MATCH: regenerated EK equals EK certificate public key
```

The EK context was flushed and its files deleted; `handles-transient` returned empty and no persistent handle was created. Combined with the P0 result that this certificate validates to the official Nuvoton TPM Root CA 1110, the endorsement side of the `tpm_devid` proof-of-residency path is now proven to the extent possible before P3: the server's `verifyEKsMatch` check compares exactly these two values.

## Step 2 — Disposable two-tier spike CA

| Role | Subject | Serial | Validity | SHA-256 fingerprint |
|---|---|---|---|---|
| Spike root CA | `O=incusos-spire spike, CN=spike root CA` | `58C0CB9CB899FE014AC66F82DC112752A2AE05E1` | 2026-08-16 → 2036-08-13 | `b057b3f2023413fdec184c6262e1de4d760d0943ffd677762adfb1a7510db1eb` |
| Spike DevID issuing CA | `O=incusos-spire spike, CN=spike DevID issuing CA` | `598B7D5DDAB39F6C59C41DB9E69EBB7072C85FDC` | 2026-08-16 → 2036-08-13 | `ce054839ab4860909dea71785fd9caa6739cdc3b9e9410daf8513ce503ef9802` |

Root is `CA:TRUE, pathlen:1`; the issuing CA is `CA:TRUE, pathlen:0`. `openssl verify` of the issuing CA against the root returned `OK`.

Published bundles on the CA volume, for P2 consumption:

- `/ca/spike-devid-root-bundle.pem` — root only, intended for the server's `devid_ca_path`.
- `/ca/spike-devid-ca-chain.pem` — issuing CA plus root.

Every CA private key is disposable and exists only on `spike-ca-state`. No key material appears in this journal.

## Step 3 — DevID key creation

Templates used:

- Parent: `SRKTemplateHighRSA` — RSA-2048, SHA-256 name algorithm, AES-128-CFB inner symmetric, attributes `fixedTPM|fixedParent|sensitiveDataOrigin|userWithAuth|noDA|restricted|decrypt`, empty `unique` field (TCG H-1 high range). Created transiently under the owner hierarchy with an empty hierarchy password and a random 32-byte object auth.
- DevID: RSA-2048, SHA-256 name algorithm, `RSASSA` with SHA-256, attributes `fixedTPM|fixedParent|sensitiveDataOrigin|userWithAuth|sign`. Unrestricted so it can sign server challenge material; `fixedTPM|fixedParent` makes the private key non-exportable and non-migratable.
- DevID key password: empty, matching the agent's default `devid_password`.

Provisioning output:

```json
{
  "step": "provision",
  "common_name": "spike-host-devid",
  "srk_template": "SRKTemplateHighRSA (TCG H-1, empty unique)",
  "srk_public_sha256": "d7c640945f6361aef01190faf2325a90952934dadd29f9b6ba1b3dfa807fb9d7",
  "devid_template": "RSA-2048 RSASSA-SHA256, fixedTPM|fixedParent|sensitiveDataOrigin|userWithAuth|sign",
  "devid_pub_blob_bytes": 280,
  "devid_priv_blob_bytes": 190,
  "devid_pub_blob_sha256": "948dedb7c59cb545089ff3dfe9f555b780252e13814972dcc2293721aa806512",
  "devid_priv_blob_sha256": "c95f777b6e7addfaa788b1b16bfeaa78fad034959022b6973a57aa313c256dc5",
  "devid_public_key_sha256": "19ca377394d5fddbed2b60ac918bb4df8632f96f79f3a530735963d2996e8439",
  "devid_key_password": "empty",
  "persistent_objects_made": 0,
  "nv_writes_made": 0
}
```

The digests identify the blobs; they are not the blob contents. The private blob itself remains only on the spike volume.

The CSR was signed by the TPM-resident key itself through a `crypto.Signer` adapter, which proves possession at creation time.

## Step 4 — Certificate issuance

The issuing CA signed the CSR with `basicConstraints=critical,CA:FALSE` and `keyUsage=critical,digitalSignature`.

| Field | Value |
|---|---|
| Subject | `O=incusos-spire spike, CN=spike-host-devid` |
| Issuer | `O=incusos-spire spike, CN=spike DevID issuing CA` |
| Serial | `2ACAF56763F64360D539F6ADBAB5B23A6CBBD545` |
| Validity | 2026-08-16 → 2027-08-16 |
| SHA-256 fingerprint | `fe8a0b6c45632b8dcb8b51d89911bab737f0cad87f8a4c3396307ece8ff44c24` |
| Public key digest | `19ca377394d5fddbed2b60ac918bb4df8632f96f79f3a530735963d2996e8439` |

The certificate public key digest equals the DevID blob public key digest, so the certificate is bound to the TPM-resident key.

`/state/devid.pem` holds the leaf followed by the issuing CA, matching the server's leaf-plus-intermediates expectation.

Expected P3 selectors, derived from these values:

- `tpm_devid:subject:cn:spike-host-devid`
- `tpm_devid:issuer:cn:spike DevID issuing CA`
- `tpm_devid:fingerprint:` over the leaf certificate

## Step 5 — TPM object diff (H4 verdict)

| Property | P0 baseline | After P1 provisioning | After host reboot |
|---|---|---|---|
| Persistent handles | `0x81000001` | `0x81000001` | `0x81000001` |
| `TPM2_PT_HR_PERSISTENT` | `0x1` | `0x1` | `0x1` |
| NV indices | `0x1C00002`, `0x1C0000A` | `0x1C00002`, `0x1C0000A` | `0x1C00002`, `0x1C0000A` |
| NV index sizes | 990 B, 789 B | 990 B, 789 B | unchanged |
| `TPM2_PT_NV_COUNTERS` | `0x0` | `0x0` | `0x0` |
| Transient handles after cleanup | none | none | none |
| `ownerAuthSet` / `endorsementAuthSet` / `lockoutAuthSet` | `0` / `0` / `0` | `0` / `0` / `0` | `0` / `0` / `0` |
| `inLockout` | false | false | false |
| `TPM2_PT_LOCKOUT_COUNTER` | `0x0` | `0x0` | `0x0` |

The diff is empty. The host-owned persistent object `0x81000001` was never touched. The dictionary-attack counter never moved, confirming no authorization failure occurred.

## Step 6 — Self-check before reboot

The self-check recreates the SRK with a **fresh random auth value**, different from the provisioning-time value, then exercises SPIRE's exact signing path:

```json
{
  "step": "selfcheck",
  "srk_recreated_with": "fresh random auth value",
  "blob_load": "ok",
  "tpm_hash_and_sign": "ok",
  "signature_verifies": true,
  "cert_matches_public_blob": true,
  "certificate_subject": "CN=spike-host-devid,O=incusos-spire spike",
  "certificate_issuer": "CN=spike DevID issuing CA,O=incusos-spire spike"
}
```

This proves three things at once: the blobs do not depend on the provisioning-time parent auth, `TPM2_Hash` plus `TPM2_Sign` with a validation ticket works on this key, and the resulting signature verifies against the issued certificate.

## Step 7 — Host reboot and durability

Reboot command: `incus admin os system reboot ovh-incusos: --force`. The API returned within roughly 75 seconds.

Post-reboot host state:

```json
{
  "secure_boot_enabled": true,
  "tpm_status": "ok",
  "system_state_is_trusted": true,
  "system_state_status": "system state is fully trusted",
  "encrypted_volumes": [
    { "state": "unlocked (TPM)", "volume": "root" },
    { "state": "unlocked (TPM)", "volume": "swap" }
  ],
  "recovery_keys_retrieved": true
}
```

All four Secure Boot certificate fingerprints match the P0 baseline. The enrollment container returned to `RUNNING` without intervention, and the self-check passed again with identical results, so the blob triplet survives a host reboot and a TPM power cycle.

## Commands exercised

Host and volume setup:

```text
incus storage volume create ovh-incusos:local spike-spire-agent-state
incus storage volume create ovh-incusos:local spike-ca-state
incus init docker:debian:trixie ovh-incusos:spike-devid-enroll -c 'oci.entrypoint=sleep infinity'
incus config device add ovh-incusos:spike-devid-enroll tpm unix-char source=/dev/tpmrm0 path=/dev/tpmrm0
incus config device add ovh-incusos:spike-devid-enroll state disk pool=local source=spike-spire-agent-state path=/state
incus config device add ovh-incusos:spike-devid-enroll ca disk pool=local source=spike-ca-state path=/ca
incus start ovh-incusos:spike-devid-enroll
incus admin os system reboot ovh-incusos: --force
```

TPM reads and the transient EK check, each with `TPM2TOOLS_TCTI=device:/dev/tpmrm0`:

```text
tpm2_getcap handles-persistent | handles-transient | handles-nv-index | properties-variable
tpm2_nvreadpublic
tpm2_createek -G rsa -c ek.ctx -u ek.tpmpub
tpm2_readpublic -c ek.ctx -f pem -o ek-live.pem
tpm2_nvread -C o 0x1c00002 -o ek-cert.der
tpm2_flushcontext -t
```

Provisioning and verification:

```text
spike-devid provision spike-host-devid
spike-devid selfcheck
openssl x509 -req -in /state/devid.csr -CA devid-ca/spike-devid-ca.pem -CAkey devid-ca/spike-devid-ca.key \
  -CAcreateserial -days 365 -sha256 -extfile /tmp/devid-leaf.ext
openssl verify -CAfile root/spike-root-ca.pem -untrusted devid-ca/spike-devid-ca.pem /state/devid.pem
```

## Cleanup

- Deleted the enrollment container `spike-devid-enroll` after the post-reboot verification.
- Retained `spike-spire-agent-state` (P3 consumes the blob triplet) and `spike-ca-state` (P3 negative case (b) needs the issuing CA to sign a foreign-TPM DevID).
- No TPM object to roll back: none was created.
- Temporary EK files and leaf extension files removed inside the container before deletion.

## Teardown inventory additions

Appended per the plan's Appendix E requirement:

| Class | Object | Removal |
|---|---|---|
| 3 | Incus volume `local/spike-spire-agent-state` | P11 |
| 4 | Incus volume `local/spike-ca-state` (spike root and issuing CA keys) | P11 |
| 6 | TPM objects | none created; P11 diff must stay empty |

## Handoff to P2 and P3

Server configuration inputs now available:

- `devid_ca_path` → spike root CA, published at `/ca/spike-devid-root-bundle.pem` on `spike-ca-state`.
- `endorsement_ca_path` → Nuvoton TPM Root CA 1110, fingerprint `2782e51a95e86d9557fe4204316cf805bd6f5898f81f9732e944d742bcdc5f54`, source recorded in the P0 evidence.

Agent configuration inputs:

```hcl
tpm_device_path = "/dev/tpmrm0"
devid_cert_path = "<spike-spire-agent-state>/devid.pem"
devid_priv_path = "<spike-spire-agent-state>/devid.priv.blob"
devid_pub_path  = "<spike-spire-agent-state>/devid.pub.blob"
```

Hierarchy password fields stay empty, matching the observed TPM posture. `devid_password` stays empty.

Open items P1 did not prove, by design:

- End-to-end `tpm_devid` node attestation, including credential activation against the EK. That is P3's critical gate.
- Whether the agent container can reach the TPM concurrently with IncusOS disk-unlock activity under sustained load.
- Certificate lifecycle. The leaf is valid for one year with no renewal path, which is acceptable for a spike and must not be copied into production design.

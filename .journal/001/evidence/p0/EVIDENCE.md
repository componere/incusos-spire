# P0 Evidence — Recovery Readiness and TPM Inventory

**Captured:** 2026-08-15 20:53 PDT  
**Host:** `ovh-incusos` (`147.135.105.83:8443`)  
**Decision:** **NO-GO at G0. Do not perform TPM mutation or start P1/P2.**

## Scope

P0 inspected the live IncusOS security state and physical TPM through a temporary Debian Trixie OCI application container. The TPM character device was passed through at `/dev/tpmrm0`. TPM commands were limited to capability, public-area, PCR-bank, handle, NV-public, and `NO_DA` endorsement-certificate reads. No hierarchy, PCR, persistent-object, or NV-index mutation command ran.

The temporary container was deleted. The host workload list is empty again.

## G0 result

| Check | Result | Evidence |
|---|---|---|
| Recovery material stored outside repositories | **BLOCKED** | IncusOS reports recovery keys retrieved, but no matching metadata-only record was found in the unlocked Bitwarden vault. Retrieval from an offline record is unconfirmed. |
| IncusOS Secure Boot and TPM health | PASS | `secure_boot_enabled=true`; `tpm_status=ok`. |
| IncusOS system trust and encrypted-volume unlock | PASS | `system_state_is_trusted=true`; root and swap are `unlocked (TPM)`. |
| TPM hierarchy and dictionary-attack state | **FAIL** | `ownerAuthSet=0`, `endorsementAuthSet=0`, `lockoutAuthSet=0`, `inLockout=0`, but `TPM2_PT_LOCKOUT_COUNTER=8` with `TPM2_PT_MAX_AUTH_FAIL=10`. P0 requires a zero counter. |
| TPM persistent and NV namespaces inventoried | PASS | One persistent object and two TCG EK certificate indices found; all are protected from spike use. |
| Endorsement certificate chain discoverable | PASS | RSA and ECC EK certificates both validate directly to the official Nuvoton TPM Root CA 1110. |
| Cleanup and unchanged host security state | PASS | Inspection container deleted; empty workload list; final IncusOS security state matches the initial state. |

Two independent blockers keep G0 closed:

1. Recovery material exists according to IncusOS, but its offline storage and retrievability have not been confirmed.
2. The physical TPM dictionary-attack counter is already `8/10`. No attempt was made to clear or reset it.

## Recovery readiness

Metadata-only checks established:

- `.state.encryption_recovery_keys_retrieved=true`
- one system encryption recovery key is present
- one `local` pool recovery key is present
- no drive recovery key is reported
- Bitwarden was unlocked and searched by host name, IP address, `IncusOS`, and `OVH`; no matching record was returned

**Correction, 2026-08-15 21:03 PDT:** The initial P0 `incus admin os system security show` invocation emitted the current system and pool recovery-key values into the harness tool output. The values were not copied into repository or journal files, but they are present in the session transcript and must be treated as exposed to that log.

The live IncusOS endpoint still returns both values. The operator can capture them without terminal output by pausing any clipboard-history tool and running:

```sh
incus admin os system security show ovh-incusos: --format json \
  | jq -c '{system_recovery_keys: .config.encryption_recovery_keys, pool_recovery_keys: .state.pool_recovery_keys}' \
  | pbcopy
```

Paste the clipboard into the body of a Bitwarden Secure Note named `ovh-incusos recovery material`, save it, clear the clipboard with `printf '' | pbcopy`, then lock and unlock Bitwarden to prove the item is available from the vault. Do not paste either value into chat, a shell command, or a repository file.

## IncusOS baseline

Before and after P0:

- IncusOS image: `202608102114`
- Incus server: `7.3`
- architecture: `x86_64`
- kernel: `7.1.8-zabbly+`
- storage: ZFS `2.4.3-1`, pool `local`
- workloads: none after cleanup
- managed networks: `incusbr0` NAT bridge and `uplink` physical network
- Secure Boot: enabled
- TPM: `ok`
- system state: fully trusted
- encrypted volumes: root and swap unlocked by TPM

Secure Boot certificates remained unchanged:

| Type | Subject | SHA-256 fingerprint |
|---|---|---|
| PK | `Incus OS - Secure Boot PK R1` | `26dce4dbb3de2d72bd16ae91a85cfeda84535317d3ee77e0d4b2d65e714cf111` |
| KEK | `Incus OS - Secure Boot KEK R1` | `9a42866f496834bde7e1b26a862b1e1b6dea7b78b91a948aecfc4e6ef79ea6c1` |
| db | `Incus OS - Secure Boot 2025 R1` | `21b6f423cf80fe6c436dfea0683460312f276debe2a14285bfdc22da2d00fc20` |
| db | `Incus OS - Secure Boot 2026 R1` | `2243c49fcf6f84fe670f100ecafa801389dc207536cb9ca87aa2c062ddebfde5` |

## Inspection environment

- OCI image: `docker:debian:trixie`
- container: `spike-tpm-inspect` (deleted)
- TPM path: `/dev/tpmrm0`
- `tpm2-tools`: `5.7-1`
- OpenSSL: `3.5.6-1~deb13u2`
- TCTI: `device:/dev/tpmrm0`

The package installation emitted expected permission warnings for container-inaccessible kernel measurement files. TPM capability and certificate reads succeeded.

## TPM fixed properties

| Property | Value |
|---|---|
| Family | TPM 2.0 |
| Specification revision | `1.16` (`0x74`) |
| Manufacturer | `NTC` (`0x4E544300`, Nuvoton) |
| Vendor strings | `rls`, `NPCT` |
| Vendor TPM type | `0x1` |
| Firmware version 1 | `0x00010003` |
| Firmware version 2 | `0x00010000` |
| PCR count | 24 |
| Input buffer | 1024 bytes |
| Maximum command/response | 2048 bytes each |
| Maximum digest | 32 bytes |
| Minimum persistent slots | 7 |
| Maximum NV indices | 2048 |

Supported algorithms:

`rsa`, `sha1`, `hmac`, `aes`, `mgf1`, `keyedhash`, `xor`, `sha256`, `rsassa`, `rsaes`, `rsapss`, `oaep`, `ecdsa`, `ecdh`, `ecdaa`, `ecschnorr`, `kdf1_sp800_56a`, `kdf1_sp800_108`, `ecc`, `symcipher`, `ctr`, `ofb`, `cfb`.

PCR banks:

- SHA-256: PCRs 0–23 selected
- SHA-1: no PCRs selected

## TPM variable properties

| Property | Value |
|---|---|
| Owner auth set | false |
| Endorsement auth set | false |
| Lockout auth set | false |
| In lockout | false |
| TPM-generated EPS | true |
| Persistent objects | 1 |
| NV indices | 2 |
| NV counters | 0 |
| Dictionary-attack counter | **8** |
| Maximum auth failures | **10** |
| Lockout interval | 7200 seconds (`0x1C20`) |
| Lockout recovery | 86400 seconds (`0x15180`) |

The dictionary-attack counter was read again after both EK certificate reads and remained `8`; the reads did not raise it.

## Persistent and NV inventory

### Existing persistent object

`0x81000001` is an ECC P-256 restricted decryption object:

- name algorithm: SHA-256
- attributes: `fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt`
- symmetric inner wrapper: AES-128-CFB
- name: `000bfdac917916138df18b3af90e7cc5b64f52a3d64edd51f158c95c8e947c8ba6fb`

Treat it as host-owned. Never evict, replace, or reuse it.

### Existing NV indices

| Index | Purpose | Size | Attributes |
|---|---|---:|---|
| `0x01C00002` | TCG RSA EK certificate | 990 bytes | `ppwrite|writeall|ppread|ownerread|authread|policyread|no_da|written|platformcreate` |
| `0x01C0000A` | TCG ECC EK certificate | 789 bytes | same |

Treat both indices as manufacturer/platform-owned. Never undefine or overwrite them.

## Endorsement certificates

Both leaf certificates have an empty subject and the issuer:

`CN=Nuvoton TPM Root CA 1110 + O=Nuvoton Technology Corporation + C=TW`

The ECC leaf certificate also records:

- TPM manufacturer: `id:4E544300`
- TPM model: `NPCT6xx`
- TPM version: `id:13`
- TPM specification: 2.0 revision `0x74`
- EKU: Endorsement Key Certificate
- AIA: official Nuvoton Root CA 1110 URL

| Leaf | Public key | Serial | Validity | SHA-256 fingerprint | Verification |
|---|---|---|---|---|---|
| RSA EK | RSA 2048, exponent 65537 | `FD2587CF1911B94DD89A` | 2019-11-13 to 2039-11-09 | `11768ed6acd752c02a7aa3ad6f1fa56300899e3b0d093ac86c230870e8d13f03` | OK |
| ECC EK | P-256 | `E15509967332B5C1A542` | 2019-11-13 to 2039-11-09 | `294355413c507cda29f2c282bb1e636e3d92ff45d77af24c30556691420aaa9e` | OK |

Official root:

- source: <https://www.nuvoton.com/security/NTC-TPM-EK-Cert/Nuvoton%20TPM%20Root%20CA%201110.cer>
- subject/issuer: `CN=Nuvoton TPM Root CA 1110 + O=Nuvoton Technology Corporation + C=TW`
- serial: `1038AA9F649AA863`
- validity: 2015-05-11 to 2035-05-07
- SHA-256 fingerprint: `2782e51a95e86d9557fe4204316cf805bd6f5898f81f9732e944d742bcdc5f54`
- `openssl verify` result for both leaves: `OK`

Manufacturer reference: <https://www.nuvoton.com/export/sites/nuvoton/files/security/Nuvoton_TPM_EK_Certificate_Chain.pdf>

## Collision-free spike namespace

No namespace object was allocated. The following ranges are reservations for later gated experiments, not live TPM state and not application configuration syntax.

| Class | Protected existing allocation | Reserved spike range | First candidate | P0 action |
|---|---|---|---|---|
| Persistent object | `0x81000001` | `0x81010000`–`0x8101000F` | `0x81010001` | none |
| NV index | `0x01C00002`, `0x01C0000A` | `0x01810000`–`0x0181000F` | `0x01810000` | none |

Rules for any later allocation:

1. Prefer serialized TPM blobs and zero new persistent/NV objects.
2. Re-run the full persistent-handle and NV-index inventory immediately before allocation.
3. Allocate only an explicitly named object in the reserved range.
4. Record the exact creation and deletion commands before creation.
5. Compare the full inventory before and after cleanup; never clear a hierarchy or use `tpm2_clear`.

The owner NV range follows the TCG reserved-handle registry; `0x01C00000`–`0x01C07FFF` is reserved for EK certificates. Reference: <https://trustedcomputinggroup.org/wp-content/uploads/RegistryOfReservedTPM2HandlesAndLocalities_v1p1_pub.pdf>.

## Commands exercised

Host/API reads:

```text
incus admin os system security show ovh-incusos: --format json
incus query ovh-incusos:/1.0
incus query ovh-incusos:/1.0/resources
incus list ovh-incusos: --format json
incus network list ovh-incusos: --format json
incus storage list ovh-incusos: --format json
```

Temporary container lifecycle:

```text
incus init docker:debian:trixie ovh-incusos:spike-tpm-inspect -c 'oci.entrypoint=sleep infinity'
incus config device add ovh-incusos:spike-tpm-inspect tpm unix-char source=/dev/tpmrm0 path=/dev/tpmrm0
incus start ovh-incusos:spike-tpm-inspect
incus delete ovh-incusos:spike-tpm-inspect --force
```

TPM reads, each with `TPM2TOOLS_TCTI=device:/dev/tpmrm0`:

```text
tpm2_getcap properties-fixed
tpm2_getcap properties-variable
tpm2_getcap algorithms
tpm2_getcap pcrs
tpm2_getcap handles-persistent
tpm2_readpublic -c 0x81000001
tpm2_getcap handles-nv-index
tpm2_nvreadpublic
tpm2_nvread -C o 0x01C00002 -o /tmp/ek-rsa.der
tpm2_nvread -C o 0x01C0000A -o /tmp/ek-ecc.der
```

The EK indices are `NO_DA`, owner auth is unset, and each certificate was read once without retry. The counter remained unchanged.

## Cleanup

- Deleted `spike-tpm-inspect` and its temporary certificate files.
- Confirmed `incus list ovh-incusos:` returns an empty array.
- Confirmed final Secure Boot, TPM health, trust, encrypted-volume unlock, recovery-key-retrieved flag, and Secure Boot certificate fingerprints match the initial baseline.
- No host reboot was needed because no TPM or boot-policy mutation occurred.

## Safe continuation condition

Do not run P1, P2, or any TPM-authorized/mutating experiment until both conditions are true:

1. The operator confirms the IncusOS system and pool recovery material is stored and retrievable outside all repositories; record only that confirmation, never the key.
2. A read-only `tpm2_getcap properties-variable` reports `TPM2_PT_LOCKOUT_COUNTER: 0x0`; investigate or allow recovery without clearing/resetting the TPM, then confirm the counter is stable across a second read.

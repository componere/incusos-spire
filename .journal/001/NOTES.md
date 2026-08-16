---
id: 001
title: Repository kickoff
started: 2026-08-15
---

## 2026-08-15 18:52 — Kickoff
Goal for the session: Begin work in the new `componere/incusos-spire` repository with persistent session context.
Current state of the world: The public repository exists from `meigma/template-go`, is cloned locally, and the `journal/jmgilman` worktree is initialized and published.
Plan: Capture the next substantive request, work incrementally, and record meaningful checkpoints here.

## 2026-08-15 18:54 — Prior design context loaded
Reviewed `SPIRE Integration Evaluation.md`. The working direction is an Incus-level integration: run the host SPIRE Agent as an OCI application container with physical `/dev/tpmrm0` passthrough and `tpm_devid`, then use the experimental SPIFFE Broker API plus an Incus-aware `AttestReference` plugin to derive guest selectors from Incus state. The preferred VM end state is a guest-local SPIRE Agent bootstrapped through an Incus-authenticated one-time nonce and `x509pop` SPIFFE exchange.
Highest-risk unknowns are physical TPM/LDevID enrollment, least-privilege Incus API access, secure guest-to-instance binding and exchange-credential delivery, and Broker API instability. Next work should prototype Phase 0 TPM passthrough before committing to the full architecture.

## 2026-08-15 19:00 — Mac spike environment selected
Created `spike/incusos-macos` at `.wt/spike-incusos-macos` from `origin/master`. Official IncusOS documentation supports aarch64 installation on VMware Fusion with UEFI Secure Boot, custom IncusOS keys, and a vTPM. This Mac has Fusion 25.0.0, 128 GiB RAM, 251 GiB free disk, and Apple reports nested virtualization support.
Decision: use a local Fusion IncusOS VM first to prove reproducible boot, Incus application containers, vTPM `/dev/tpmrm0` passthrough, and host-side SPIRE plumbing. Treat it as a software-TPM functional lab, not proof of physical TPM security. Validate nested Incus VMs explicitly; if Fusion does not expose nested virtualization, use a separate Apple Virtualization Framework Linux VM for guest/nested SPIRE work. Final `tpm_devid` claims still require a bare-metal TPM 2.0 machine.

## 2026-08-15 19:15 — Local control CLIs enabled
Fusion was updated to 26.0.0/build 25388279. Exposed `vmcli`, `vmrun`, `vmware-vdiskmanager`, and `ovftool` through `~/.local/bin`; all resolve against the Fusion 26 installation. The local Incus 7.2 client already has a TLS client certificate at `~/.config/incus/client.crt`, ready to embed in the IncusOS install seed and use for the future `incusos-spike` remote.

## 2026-08-15 19:45 — IncusOS Mac spike executed
Installed seeded aarch64 IncusOS `202608102114` under Fusion 26 in `~/Virtual Machines.localized/IncusOS-Spike.vmwarevm` with 4 vCPUs, 8 GiB RAM, 64 GiB disk, Secure Boot, and the IncusOS 2025/2026 DB plus KEK certificates. Command-line Fusion configuration did not materialize a usable VMware vTPM, so the successful installation used the IncusOS `security.missing_tpm` path. IncusOS reports Secure Boot enabled, `tpm_status: swtpm`, `system_state_is_trusted: false`, encrypted root/swap unlocked by TPM, and Incus 7.3. Recovery keys were retrieved through the API but are intentionally not copied into the journal.
Fusion networking initially had no running DHCP/NAT services after the upgrade. Running privileged `vmnet-cli --configure`, `vmnet-cli --start`, and creating `/Library/Preferences/VMware Fusion/promiscAuthorized` fixed it; the stable remote is `incusos-spike` at `172.16.140.134`.
Proved the core Incus boundary with an OCI application container from `docker:debian:trixie`: `/dev/tpmrm0` attaches through an Incus `unix-char` device as a root-owned mode-0660 character device. `tpm2_getcap` identifies TPM 2.0, IBM software TPM revision 1.64, and `tpm2_pcrread sha256:0,7` succeeds. The container and TPM access survive both container restart and a graceful IncusOS host reboot.
Proved the unmodified ARM64 `ghcr.io/spiffe/spire-agent:1.15.2` OCI image runs under IncusOS and reports version 1.15.2 with `/dev/tpmrm0` configured on the instance. This does not yet prove `tpm_devid`; DevID provisioning, endorsement trust, SPIRE Server attestation, and persistent agent configuration remain separate experiments.
Nested Incus VMs are unavailable in this Fusion guest. Creating a Debian VM fails deterministically with `KVM support is missing (no /dev/kvm)`. Use this Fusion IncusOS system for host/container/SPIRE integration and use a separate Apple Virtualization Framework Linux environment or bare metal for nested VM work. A physical TPM machine remains mandatory before validating the production host identity claim.

## 2026-08-15 20:00 — Parallels rejected as primary alternative
Current Parallels Desktop 26 documentation supports EFI/Secure Boot controls and a TPM device, but does not document custom Secure Boot PK/KEK/DB enrollment or confirm TPM 2.0 behavior for Linux ARM64 guests. A plausible IncusOS experiment would therefore require degraded mode with Secure Boot disabled and a Parallels vTPM; it is not a documented IncusOS configuration. Parallels explicitly does not support nested virtualization on Apple silicon, so it cannot fix the missing `/dev/kvm` result. Do not purchase it for this spike; keep Fusion for the host/container lab and use Apple Virtualization Framework or bare metal for nested VMs.

## 2026-08-15 20:09 — OVH bare metal selected for the full spike
Reviewed `~/code/ovh/docs/docs/runbooks/incusos-bare-metal.md` and checked the live `ovh-incusos` remote. The idle x86_64 host has 16 CPU threads, roughly 66 GiB RAM, a physical TPM 2.0 with `tpm_status: ok`, IncusOS Secure Boot keys enrolled, a fully trusted system state, TPM-unlocked root/swap, ZFS `local`, NAT `incusbr0`, and Incus virtual-machine API support. Use it for the end-to-end SPIRE spike, including physical `tpm_devid` work and guest VMs. Treat TPM provisioning as a controlled operation: save recovery material first, allocate explicit non-conflicting persistent/NV handles, and never clear or reset TPM hierarchies because IncusOS disk unlock depends on the same TPM.

## 2026-08-15 20:10 — OVH KVM verified
Created and started an empty x86_64 Incus VM on `ovh-incusos`; it reached `RUNNING` with a QEMU PID, TAP interface, and 105 MiB current memory. Deleted the capability-check VM and confirmed the remote returned to an empty workload list. This closes the Mac lab's `/dev/kvm` gap without leaving a guest image or instance behind.

## 2026-08-15 20:34 — Full spike plan completed
Delegated the end-to-end design to a planning agent with the prior evaluation, Mac evidence, live OVH facts, runbook, TPM safety invariants, and SPIRE 1.15.2 references preloaded. Reviewed and refined the result into `SPIKE_PLAN.md`. The plan gates all persistent TPM mutation behind recovery readiness and namespace inventory, proves physical `tpm_devid` before custom Broker work, separates the read-only Incus attestor identity from the bootstrap writer, treats the guest nonce honestly as a bearer credential, requires atomic single-use redemption, and covers lifecycle/adversarial cases through final teardown and go/no-go.

## 2026-08-15 20:53 — P0 executed; G0 blocked
Ran the P0 recovery-readiness and physical-TPM inventory on `ovh-incusos` through a temporary Debian Trixie OCI application container with `/dev/tpmrm0`. Secure Boot, TPM health, full system trust, and TPM-unlocked root/swap remained unchanged; the container was deleted and the workload list is empty. The Nuvoton NPCT6xx exposes RSA and ECC EK certificates that both validate to the official Nuvoton TPM Root CA 1110. Inventory found one protected persistent ECC restricted-decryption object at `0x81000001` and only the two TCG EK certificate NV indices. G0 is closed because Bitwarden contains no discoverable recovery record for the host and the TPM dictionary-attack counter is already `8/10`, although it did not increase during `NO_DA` EK reads. No TPM mutation or reboot occurred. Full commands, fingerprints, reserved collision-free ranges, cleanup proof, and continuation conditions are in `evidence/p0/EVIDENCE.md`.

## 2026-08-15 21:03 — Recovery-key exposure record corrected
Correction to the P0 evidence: the initial unfiltered `incus admin os system security show` tool call emitted the current system and `local` pool recovery-key values into the harness transcript. They were not written to repository or journal files, but must be treated as exposed to session logs. IncusOS still returns both values. The safe capture path is to filter only those fields directly into the macOS clipboard, paste the JSON into a Bitwarden Secure Note, clear the clipboard, and prove the item survives a vault lock/unlock cycle. Do not rotate keys while G0 remains closed; first preserve the current recovery path and resolve the TPM dictionary-attack counter.

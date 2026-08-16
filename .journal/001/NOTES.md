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

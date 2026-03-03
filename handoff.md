# kprotect Project Handoff

This file tracks project state across AI sessions. For the full history of changes, see the `session_handoff/` directory.

## Current Focus: Automated Releases (CI/CD)

### Latest Session (2026-03-03 - CI/CD & eBPF Automation) Summary:
- **Automation**: Implemented `.github/workflows/release.yml` for unified GitHub Releases (Core + GUI).
- **Toolchain**: Fixed the "Component Missing" error by switching to an "Honest CI" toolchain (building `std` from source for eBPF).
- **Hurdles**: Build is currently failing due to missing `bpf-linker` and `kprotect-pam` safety documentation.

**To continue work:**
1. Read `session_handoff/session_2026_03_03_cicd_release_automation.md` for the technical roadmap.
2. Add `# Safety` docs to `kprotect-pam/src/lib.rs`.
3. Add `cargo install bpf-linker` to workfow YAMLs and verify the Green Build.

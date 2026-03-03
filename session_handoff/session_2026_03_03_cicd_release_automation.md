# Session Handoff: CI/CD & Automated Release Automation (2026-03-03)

## Objective:
Automate the release process for `kprotect` using GitHub Actions, ensuring Core (eBPF/Daemon) and GUI (Tauri) artifacts are bundled together.

## Accomplishments:
1.  **Release Workflow**: Created `.github/workflows/release.yml` to trigger on `v*` tags, building Core packages (`cargo deb`) and GUI artifacts (`tauri-action`), then bundling them into a single GitHub draft release.
2.  **Honest CI Toolchain**: 
    - Discovered that the `bpfel-unknown-none` target cannot be installed as a pre-compiled component in Nightly.
    - Implemented the "Honest" approach: toolchain now installs `nightly` with the `rust-src` component only. `cargo` handles building the core library from source during the eBPF build phase.
3.  **Mock Verification**: Confirmed integration tests (`api_integration.rs`, `lineage_test.rs`) use `AppState::mock_test()` and are suitable for limited-privilege CI environments.
4.  **Clippy Hygiene**: Fixed several clippy warnings in `kprotect-common/src/path_matcher.rs` (`manual_strip`, `Default` implementations) to satisfy strict `-D warnings` pipeline requirements.

## Current Status & Next Steps:
The CI is currently **RED** due to two remaining build hurdles:
1.  **Missing Linker**: The `Build eBPF` job fails because `bpf-linker` is not installed on the GitHub runner.
    - *Fix Required*: Add `cargo install bpf-linker` to the workflow setup steps.
2.  **Missing Safety Docs**: `kprotect-pam` has `unsafe` functions exported for PAM. Clippy requires `# Safety` documentation sections for these.
    - *Fix Required*: Add doc comments explaining the safety requirements of the 3 PAM export functions in `kprotect-pam/src/lib.rs`.

## To Resume:
1.  Run `gh run list` to see the latest failed runs.
2.  Apply the final lints to `kprotect-pam`.
3.  Ensure `bpf-linker` is in the workflows before pushing.
4.  Once Green, push the tag `v0.2.0-beta` (force-push current) to trigger the draft release.

# kprotect — Handoff Document

> Last updated: 2026-03-03  
> See `session_handoff/` for detailed per-session logs.

---

## Current State
- **Branch**: `main` (clean, all CI passing)
- **Latest tag**: `v0.2.0-beta` — full release pipeline passes ✅
- **Release draft**: https://github.com/khoinp1012/kprotect/releases (ready to publish)

---

## Immediate Next Steps

### 1. 🔴 Align CI/CD to use local build scripts
Currently the CI workflows duplicate build logic that lives in `scripts/`. The fix is to have the workflows call the scripts instead:
- `release.yml` → call `bash scripts/build_deb.sh` (core build + Debian package)
- `release.yml` → call `bash scripts/build_gui.sh` (Tauri AppImage/deb)
- Keep env setup (LLVM, Rust toolchain, deps) in the YAML — that's environment prep, not build logic

### 2. 🔴 Verify local build end-to-end
```bash
bash scripts/build_deb.sh      # Builds eBPF + core binaries + .deb
bash scripts/build_gui.sh      # Builds Tauri GUI (AppImage + deb bundle)
sudo bash scripts/install.sh   # Install daemon, CLI, PAM, systemd service
```

### 3. 🟡 Publish v0.2.0-beta release
The GitHub release draft is ready — just review and hit Publish.

---

## Architecture Notes
- `install.sh` installs the **daemon, CLI, and PAM module** only. GUI is standalone (AppImage).
- eBPF programs must be built before the daemon: `cargo xtask build-ebpf --release`
- PAM module installed to `/lib/x86_64-linux-gnu/security/pam_kprotect.so`
- CI requires: `libpam0g-dev`, `llvm`, `clang`, `libelf-dev`, `libbpf-dev`
- Tauri plugin versions must match between `Cargo.toml` and `package.json`

---

## Session History
- [`2026-03-03`](session_handoff/2026-03-03.md) — Clippy lint cleanup, CI/CD fixes, v0.2.0-beta release pipeline

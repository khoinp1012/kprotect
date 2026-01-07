use anyhow::{Context, Result};
use aya::{Ebpf, EbpfLoader};
use aya::programs::Lsm;
use log::info;

/// Load eBPF programs and attach LSM hooks
pub fn load_ebpf() -> Result<Ebpf> {
    // Embed the bytecode at compile time
    // Path is relative to this file (src/ebpf/manager.rs) -> ../../../kprotect-ebpf/...
    let ebpf_bytes = include_bytes!("../../../kprotect-ebpf/target/bpfel-unknown-none/release/libkprotect_ebpf.so");
    info!("eBPF Bytes Length: {}", ebpf_bytes.len());
    info!("eBPF Header: {:02x} {:02x} {:02x} {:02x}", ebpf_bytes[0], ebpf_bytes[1], ebpf_bytes[2], ebpf_bytes[3]);

    // COPY to aligned buffer (heap) to prevent "error parsing ELF data" due to alignment issues
    let ebpf_bytes_aligned = ebpf_bytes.to_vec();

    let mut bpf = EbpfLoader::new()
        .load(&ebpf_bytes_aligned)
        .context("Failed to load eBPF bytecode")?;

    info!("✓ eBPF bytecode loaded");

    // CRITICAL: Attach LSM Hooks IMMEDIATELY
    attach_lsm_hook(&mut bpf, "bprm_committed_creds")?;
    attach_lsm_hook(&mut bpf, "file_open")?;
    attach_lsm_hook(&mut bpf, "task_free")?;
    info!("⚡ LSM hooks attached early - ready to track processes");

    Ok(bpf)
}

fn attach_lsm_hook(bpf: &mut Ebpf, hook_name: &str) -> Result<()> {
    let program: &mut Lsm = bpf
        .program_mut(hook_name)
        .context(format!("Failed to find program: {}", hook_name))?
        .try_into()?;
    program.load(hook_name, &aya::Btf::from_sys_fs()?)?;
    program.attach()?;
    info!("✓ Attached hook: {}", hook_name);
    Ok(())
}

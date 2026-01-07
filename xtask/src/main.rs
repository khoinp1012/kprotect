use anyhow::{Context, Result};
use clap::Parser;
use std::process::Command;

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Subcommand,
}

#[derive(Parser)]
enum Subcommand {
    /// Build the eBPF program
    BuildEbpf {
        /// Build in release mode
        #[arg(long)]
        release: bool,
    },
}

fn main() -> Result<()> {
    let args = Args::parse();

    match args.command {
        Subcommand::BuildEbpf { release } => build_ebpf(release),
    }
}

fn build_ebpf(release: bool) -> Result<()> {
    let mut cmd = Command::new("cargo");
    cmd.current_dir("kprotect-ebpf")
        .arg("+nightly")
        .arg("build")
        .arg("--target=bpfel-unknown-none")
        .arg("-Z")
        .arg("build-std=core");

    if release {
        cmd.arg("--release");
    }

    let status = cmd
        .status()
        .context("Failed to execute cargo build for eBPF")?;

    if !status.success() {
        anyhow::bail!("eBPF build failed");
    }

    let profile = if release { "release" } else { "debug" };
    println!("\n✓ eBPF program built successfully!");
    println!("  Output: kprotect-ebpf/target/bpfel-unknown-none/{}/libkprotect_ebpf.so", profile);

    Ok(())
}


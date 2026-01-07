// kprotect-daemon: Industry Standard Security Daemon
// Copyright (C) 2026 khoinp1012
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! kprotect Daemon - Industry Standard Implementation
//!
//! Features:
//! - eBPF Event Monitoring
//! - Unix Socket API
//! - Privilege Separation (UID-based)
//! - AES-256-GCM encrypted configuration
//! - Protocol v1.0 compliant

pub mod crypto;
pub mod migration;
pub mod config;
pub mod logger;
pub mod notifications;
pub mod state;
pub mod core;
pub mod ebpf;
pub mod server;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tokio::net::UnixStream;
use tokio::io::AsyncWriteExt;

const SOCKET_PATH: &str = "/var/run/kprotect.sock";

#[derive(Parser)]
#[command(name = "kprotect")]
#[command(about = "kprotect Daemon", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the daemon
    Daemon,
    /// Authorize a workflow (CLI Client)
    Authorize {
        /// Signature to authorize
        signature: String,
    },
    /// Clear all authorizations (CLI Client)
    Clear,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Daemon => {
            crate::server::startup::start_daemon().await?;
        }
        Commands::Authorize { signature } => {
            // CLI client mode: send command to socket
            send_socket_command(&format!("AUTHORIZE;{};Exact;CLI Approval", signature)).await?;
        }
        Commands::Clear => {
            send_socket_command("CLEAR").await?;
        }
    }
    Ok(())
}

async fn send_socket_command(cmd: &str) -> Result<()> {
    let mut stream = UnixStream::connect(SOCKET_PATH).await?;
    // Fix: Append newline to ensure command is processed
    let cmd = if cmd.ends_with('\n') {
        cmd.to_string()
    } else {
        format!("{}\n", cmd)
    };
    
    stream.write_all(cmd.as_bytes()).await?;
    stream.shutdown().await?;
    Ok(())
}

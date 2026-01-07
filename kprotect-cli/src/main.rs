// kprotect-cli: Command-line interface for kprotect daemon
// Copyright (C) 2026 Khoi
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

// kprotect-cli: Command-line interface for kprotect daemon
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

//! kprotect CLI - Command-line interface for kprotect daemon

use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::*;
use kprotect_client::KprotectClient;
// use tabled::{Table, Tabled, settings::Style};

#[derive(Parser)]
#[command(name = "kprotect-cli")]
#[command(about = "kprotect - eBPF-based process lineage security", long_about = None)]
#[command(version)]
struct Cli {
    /// Path to kprotect daemon socket
    #[arg(long, default_value = "/run/kprotect/kprotect.sock")]
    socket: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Ping the daemon
    Ping,
    
    /// Show daemon version
    Version,
    
    /// Show daemon capabilities
    Capabilities,
    
    /// Manage authorization patterns
    Authorize {
        #[command(subcommand)]
        action: AuthorizeAction,
    },
    
    /// Manage zones (red/green)
    Zone {
        #[command(subcommand)]
        action: ZoneAction,
    },
    
    /// Manage enrichment patterns
    Pattern {
        #[command(subcommand)]
        action: PatternAction,
    },

    /// Get log configuration
    GetLogConfig,

    /// Set log retention days
    SetLogRetention {
        /// Days to keep security events
        #[arg(long)]
        events: u32,
        /// Days to keep audit logs
        #[arg(long)]
        audit: u32,
    },

    /// Get security events
    Events {
        /// Number of events to retrieve (ignored if --stream is used)
        #[arg(short, long, default_value = "50")]
        count: usize,
        
        /// Stream live events
        #[arg(short, long)]
        stream: bool,

        /// Output as JSON (NDJSON for stream)
        #[arg(long)]
        json: bool,
    },

    /// Get audit logs
    Audit {
        /// Number of logs to retrieve
        #[arg(short, long, default_value = "50")]
        count: usize,
    },

    /// Show system status
    Status {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    
    /// Manage notification rules
    Notify {
        #[command(subcommand)]
        action: NotifyAction,
    },

    /// Start interactive mode (reads commands from stdin)
    Interactive,
}


#[derive(Subcommand)]
enum AuthorizeAction {
    /// Add an authorization pattern
    Add {
        /// Comma-separated list of process paths (e.g. "/usr/bin/bash,/usr/bin/cat")
        pattern: String,
        
        /// Match mode (Exact or Suffix)
        #[arg(short, long, default_value = "Suffix")]
        mode: String,
        
        /// Optional description
        #[arg(short, long)]
        description: Option<String>,
    },
    /// Remove an authorization pattern
    Remove {
        /// Pattern to remove (comma-separated for multi-part patterns)
        #[arg(value_delimiter = ',')]
        pattern: Vec<String>,
        
        /// Match mode: 'exact' or 'suffix'
        #[arg(short, long, default_value = "suffix")]
        mode: String,
    },
    /// List all authorized patterns
    List {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Clear all authorized patterns
    Clear,
}

#[derive(Subcommand)]
enum ZoneAction {
    /// Add a zone pattern
    Add {
        /// Zone type (red or green)  
        zone_type: String,
        /// Pattern (e.g. *.secret)
        pattern: String,
    },
    /// Remove a zone pattern
    Remove {
        /// Zone type (red or green)
        zone_type: String,
        /// Pattern to remove
        pattern: String,
    },
    /// List all zones
    List {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum PatternAction {
    /// Add an enrichment pattern
    Add {
        /// Pattern path (e.g. /usr/bin/python*)
        pattern: String,
    },
    /// Remove an enrichment pattern
    Remove {
        /// Pattern to remove
        pattern: String,
    },
    /// List all patterns
    List {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub enum NotifyAction {
    /// Add a notification rule
    Add {
        /// Human-readable name
        #[arg(short, long)]
        name: String,
        /// Comma-separated events (Verified, Blocked)
        #[arg(short, long)]
        events: String,
        /// Optional path pattern (glob)
        #[arg(short, long)]
        path: Option<String>,
        /// Action type (Script or Webhook)
        #[arg(short, long)]
        action: String,
        /// Destination (Script path or Webhook URL)
        #[arg(short, long)]
        dest: String,
        /// Timeout in seconds
        #[arg(short, long, default_value = "30")]
        timeout: u32,
    },
    /// Remove a notification rule
    Remove {
        /// Rule ID
        id: u32,
    },
    /// Toggle a rule on/off
    Toggle {
        /// Rule ID
        id: u32,
        /// Enabled status (true/false)
        enabled: bool,
    },
    /// List all notification rules
    List {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Show notification statistics
    Stats {
        /// Optional rule ID to show stats for a specific rule
        #[arg(short, long)]
        rule_id: Option<u32>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    // For streaming processing, we might use direct socket connection
    let socket_path = cli.socket.clone();

    // Regular client for other commands
    let client = KprotectClient::with_socket_path(&cli.socket);

    match cli.command {
        Commands::Ping => {
            let response = client.ping().await?;
            println!("{} {}", "✓".green().bold(), response.bright_green());
        }
        
        Commands::Version => {
            let response = client.version().await?;
            println!("{} {}", "ℹ".blue().bold(), response.cyan());
        }
        
        Commands::Capabilities => {
            let caps = client.capabilities().await?;
            println!("\n{}", "═".repeat(50).bright_cyan());
            println!("{}",  "      kprotect Daemon Capabilities".bright_cyan().bold());
            println!("{}\n", "═".repeat(50).bright_cyan());
            
            println!("{} Version: {}  {} Protocol: {}", 
                "📦",
                caps.version.cyan(),
                "🔌",
                caps.protocol_version.cyan()
            );
            
            println!("\n{} Features:", "✨".bold());
            for feat in &caps.features {
                println!("  {} {}", "✓".green(), feat);
            }
            println!();
        }
        
        Commands::Authorize { action } => {
            match action {
                AuthorizeAction::Add { pattern, mode, description } => {
                    let pattern_list: Vec<String> = pattern.split(',')
                        .map(|s| s.trim().to_string())
                        .collect();
                        
                    let match_mode = match mode.to_lowercase().as_str() {
                        "exact" => kprotect_client::MatchMode::Exact,
                        "suffix" => kprotect_client::MatchMode::Suffix,
                        _ => anyhow::bail!("Invalid match mode. Use 'Exact' or 'Suffix'"),
                    };
                    
                    client.authorize_pattern(&pattern_list, match_mode, description.as_deref()).await?;
                    println!("\n{} {}", "✅", "Pattern authorized successfully".green().bold());
                    println!("   {} {}", "Pattern:".dimmed(), pattern.cyan());
                    println!("   {} {}", "Mode:".dimmed(), mode.cyan());
                    if let Some(desc) = description {
                        println!("   {} {}", "Description:".dimmed(), desc);
                    }
                    println!();
                }
                
                AuthorizeAction::Remove { pattern, mode } => {
                    let match_mode = match mode.to_lowercase().as_str() {
                        "exact" => kprotect_common::MatchMode::Exact,
                        "suffix" => kprotect_common::MatchMode::Suffix,
                        _ => {
                            eprintln!("❌ Invalid mode '{}'. Use 'exact' or 'suffix'", mode);
                            std::process::exit(1);
                        }
                    };
                    
                    client.revoke_pattern(pattern.clone(), match_mode).await?;
                    println!("\n{} {}", "🗑️", "Pattern revoked successfully".yellow().bold());
                    println!("   {} {}", "Pattern:".dimmed(), pattern.join(" → ").cyan());
                    println!("   {} {}", "Mode:".dimmed(), mode.cyan());
                    println!();
                }
                
                AuthorizeAction::List { json } => {
                    let patterns = client.get_patterns().await?;
                    if json {
                        println!("{}", serde_json::to_string_pretty(&patterns)?);
                    } else if patterns.is_empty() {
                        println!("\n{} {}", "ℹ".blue(), "No authorized patterns".dimmed());
                    } else {
                        println!("\n{} Authorized Patterns:", "📋".bold());
                        for (idx, p) in patterns.iter().enumerate() {
                            println!("\n  {} Pattern #{}", "→".cyan(), idx + 1);
                            println!("    {} {}", "Chain:".dimmed(), p.pattern.join(" → ").yellow());
                            println!("    {} {:?}", "Mode:".dimmed(), p.match_mode);
                            println!("    {} {}", "Description:".dimmed(), p.description.cyan());
                            println!("    {} {}", "Authorized:".dimmed(), 
                                format!("{} (Unix timestamp)", p.authorized_at)
                            );
                        }
                        println!();
                    }
                }
                
                AuthorizeAction::Clear => {
                    // Send CLEAR command to daemon
                    let _ = client.ping().await; // Placeholder check
                    // For now, just inform user to use daemon command
                    println!("\n{} {}", "⚠".yellow(), "Clear all authorizations?".bold());
                    println!("   This will remove ALL authorized patterns.");
                    println!("   Type 'yes' to confirm:");
                    
                    use std::io::{self, BufRead};
                    let stdin = io::stdin();
                    let mut line = String::new();
                    stdin.lock().read_line(&mut line)?;
                    
                    if line.trim().to_lowercase() == "yes" {
                        println!("{} {}", "✓".green(), "Sending CLEAR command to daemon...".dimmed());
                        // Temporary: send via socket directly
                        use tokio::net::UnixStream;
                        use tokio::io::AsyncWriteExt;
                        let mut stream = UnixStream::connect(&socket_path).await?;
                        stream.write_all(b"CLEAR\n").await?;
                        println!("{} {}", "✓".green().bold(), "All patterns cleared".green());
                    } else {
                        println!("{} Cancelled", "✗".red());
                    }
                }
            }
        }
        
        Commands::Zone { action } => {
            match action {
                ZoneAction::Add { zone_type, pattern } => {
                    client.add_zone(&zone_type, &pattern).await?;
                    println!("{} Added {} zone: {}", 
                        "✓".green().bold(),
                        zone_type.cyan(),
                        pattern.yellow()
                    );
                }
                ZoneAction::Remove { zone_type, pattern } => {
                    client.remove_zone(&zone_type, &pattern).await?;
                    println!("{} Removed {} zone: {}", 
                        "✓".green().bold(),
                        zone_type.cyan(),
                        pattern.yellow()
                    );
                }
                ZoneAction::List { json } => {
                    if unsafe { libc::getuid() } != 0 {
                        anyhow::bail!("This command requires root privileges (use sudo)");
                    }
                    let zones = client.list_zones().await?;
                    
                    if json {
                        println!("{}", serde_json::to_string_pretty(&zones)?);
                    } else {
                        println!("\n{} {}", "🔴", "Red Zones:".red().bold());
                        for (i, pattern) in zones.red_zones.iter().enumerate() {
                            println!("  {}. {}", (i + 1).to_string().dimmed(), pattern.yellow());
                        }
                        
                        println!("\n{} {}", "🟢", "Green Zones:".green().bold());
                        if zones.green_zones.is_empty() {
                            println!("  {}", "(none)".dimmed());
                        } else {
                            for (i, pattern) in zones.green_zones.iter().enumerate() {
                                println!("  {}. {}", (i + 1).to_string().dimmed(), pattern.cyan());
                            }
                        }
                        println!();
                    }
                }
            }
        }
        
        Commands::Pattern { action } => {
            match action {
                PatternAction::Add { pattern } => {
                    client.add_enrichment_pattern(&pattern).await?;
                    println!("{} Added pattern: {}", 
                        "✓".green().bold(),
                        pattern.yellow()
                    );
                }
                PatternAction::Remove { pattern } => {
                    client.remove_enrichment_pattern(&pattern).await?;
                    println!("{} Removed pattern: {}", 
                        "✓".green().bold(),
                        pattern.yellow()
                    );
                }
                PatternAction::List { json } => {
                    if unsafe { libc::getuid() } != 0 {
                        anyhow::bail!("This command requires root privileges (use sudo)");
                    }
                    let config = client.list_enrichment_patterns().await?;
                    
                    if json {
                        println!("{}", serde_json::to_string_pretty(&config)?);
                    } else {
                        println!("\n{} {}", "🔧", "Enrichment Patterns:".cyan().bold());
                        for (i, pattern) in config.enrichment_patterns.iter().enumerate() {
                            println!("  {}. {}", (i + 1).to_string().dimmed(), pattern.yellow());
                        }
                        println!();
                    }
                }
            }
        }

        Commands::GetLogConfig => {
            let config = client.get_log_config().await?;
            println!("\n{} {}", "📝", "Log Configuration:".cyan().bold());
            println!("   {} {} days", "Event Retention:".dimmed(), config.event_log_retention_days.to_string().yellow());
            println!("   {} {} days", "Audit Retention:".dimmed(), config.audit_log_retention_days.to_string().yellow());
            println!();
        }

        Commands::SetLogRetention { events, audit } => {
            client.set_log_retention(events, audit).await?;
            println!("\n{} {}", "✅", "Log retention updated successfully".green().bold());
            println!("   {} {} days", "Events:".dimmed(), events.to_string().cyan());
            println!("   {} {} days", "Audit:".dimmed(), audit.to_string().cyan());
            println!();
        }

        Commands::Events { count, stream, json } => {
            if stream {
                // Streaming mode - Direct socket connection
                use tokio::net::UnixStream;
                use tokio::io::{AsyncBufReadExt, BufReader, AsyncWriteExt};

                let mut socket = UnixStream::connect(&socket_path).await
                    .map_err(|e| anyhow::anyhow!("Failed to connect to daemon socket at {}: {}", socket_path, e))?;

                // Determine subscription command based on args (future proofing)
                // For now, just basic SUBSCRIBE
                socket.write_all(b"SUBSCRIBE\n").await?;

                let reader = BufReader::new(socket);
                let mut lines = reader.lines();

                while let Some(line) = lines.next_line().await? {
                    if line.starts_with("OK:") || line.starts_with("ERROR:") {
                        // Skip control messages in JSON mode, or print to stderr
                        if !json {
                            eprintln!("{}", line);
                        }
                        continue;
                    }

                    // Assume it's an event JSON
                    if json {
                        println!("{}", line);
                    } else {
                        // Pretty print for humans
                        // Try to parse basic fields to show something useful
                        match serde_json::from_str::<serde_json::Value>(&line) {
                            Ok(v) => {
                                let time = v["timestamp"].as_u64().unwrap_or(0);
                                let path = v["path"].as_str()
                                    .or_else(|| v["target"].as_str())
                                    .or_else(|| v["chain_str"].as_str())
                                    .unwrap_or("???");
                                let status = v["status"].as_str().unwrap_or("UNKNOWN");
                                let status_colored = match status {
                                    "Verified" => status.green(),
                                    "Blocked" => status.red(),
                                    _ => status.white(),
                                };
                                println!("[{}] {} {}", 
                                    chrono::DateTime::from_timestamp(time as i64, 0)
                                        .unwrap_or_default()
                                        .format("%H:%M:%S")
                                        .to_string()
                                        .dimmed(),
                                    status_colored,
                                    path
                                );
                            }
                            Err(_) => println!("{}", line), // Fallback
                        }
                    }
                }
            } else {
                // Historic fetch mode
                let events = client.get_events(count, 0).await?;
                if json {
                    // Output as JSON array
                    let json_out = serde_json::to_string_pretty(&events)?;
                    println!("{}", json_out);
                } else {
                    println!("\n{} {} (showing last {})", "📜", "Security Events:".red().bold(), events.len());
                    for e in events {
                        println!("{:?}", e);
                    }
                    println!();
                }
            }
        }

        Commands::Audit { count } => {
            let logs = client.get_audit(count, 0).await?;
            println!("\n{} {} (showing last {})", "🛡️", "Audit Logs:".blue().bold(), logs.len());
            for log in logs {
                println!("{:?}", log);
            }
            println!();
        }

        Commands::Status { json } => {
            let status = client.get_daemon_status().await?;
            let encryption = client.get_encryption_info().await?;
            let system = client.get_system_info().await?;

            if json {
                use serde_json::json;
                let wrapper = json!({
                    "daemon": status,
                    "encryption": encryption,
                    "system": system
                });
                println!("{}", serde_json::to_string(&wrapper)?);
            } else {
                println!("\n{}", "═".repeat(60).bright_cyan());
                println!("{}",  "            kprotect System Status".bright_cyan().bold());
                println!("{}", "═".repeat(60).bright_cyan());

                println!("\n{} {}", "🚀", "Daemon Status:".bold());
                println!("   {} {}s", "Uptime:".dimmed(), status.uptime_seconds.to_string().cyan());
                println!("   {} {}", "eBPF Loaded:".dimmed(), if status.ebpf_loaded { "Yes".green() } else { "No".red() });
                println!("   {} {}", "Active Conns:".dimmed(), status.active_connections.to_string().yellow());
                println!("   {} {}", "Socket:".dimmed(), status.socket_path);

                println!("\n{} {}", "🔒", "Security & Encryption:".bold());
                println!("   {} {}", "Encryption:".dimmed(), if encryption.enabled { format!("Enabled ({})", encryption.algorithm).green() } else { "Disabled".red() });
                println!("   {} {}", "Key Fingerprint:".dimmed(), encryption.key_fingerprint.cyan());
                
                println!("\n{} {}", "📊", "Policy Statistics:".bold());
                println!("   {} {}", "Authorized Patterns:".dimmed(), system.authorized_patterns.to_string().yellow());
                println!("   {} {}", "Red Zones:".dimmed(), system.red_zones.to_string().yellow());
                println!("   {} {}", "Enrichment Rules:".dimmed(), system.enrichment_patterns.to_string().yellow());

                println!("\n{} {}", "🧠", "eBPF Map Usage:".bold());
                for (name, stats) in system.ebpf_maps {
                    let usage = if stats.capacity > 0 { (stats.size as f32 / stats.capacity as f32) * 100.0 } else { 0.0 };
                    println!("   {}: {}/{} ({:.1}%)", 
                        name.dimmed(), 
                        stats.size, 
                        stats.capacity,
                        usage
                    );
                }
                println!("\n{}\n", "═".repeat(60).bright_cyan());
            }
        }

        Commands::Notify { action } => {
            match action {
                NotifyAction::Add { name, events, path, action, dest, timeout } => {
                    let event_types: Vec<kprotect_common::EventTypeFilter> = events.split(',')
                        .map(|s| match s.trim() {
                            "Verified" => kprotect_common::EventTypeFilter::Verified,
                            "Blocked" => kprotect_common::EventTypeFilter::Blocked,
                            _ => panic!("Invalid event type: {}", s),
                        })
                        .collect();
                    
                    let action_type = match action.to_lowercase().as_str() {
                        "script" => kprotect_common::ActionType::Script,
                        "webhook" => kprotect_common::ActionType::Webhook,
                        _ => anyhow::bail!("Invalid action type. Use 'Script' or 'Webhook'"),
                    };

                    client.add_notification_rule(&name, &event_types, path.as_deref(), action_type, &dest, timeout).await?;
                    println!("{} Added notification rule: {}", "✓".green().bold(), name.cyan());
                }
                NotifyAction::Remove { id } => {
                    client.remove_notification_rule(id).await?;
                    println!("{} Removed notification rule ID: {}", "✓".green().bold(), id.to_string().yellow());
                }
                NotifyAction::Toggle { id, enabled } => {
                    client.toggle_notification_rule(id, enabled).await?;
                    let status = if enabled { "enabled".green() } else { "disabled".red() };
                    println!("{} Rule {} is now {}", "✓".green().bold(), id.to_string().yellow(), status);
                }
                NotifyAction::List { json } => {
                    let rules = client.get_notification_rules().await?;
                    
                    if json {
                        println!("{}", serde_json::to_string_pretty(&rules)?);
                    } else {
                        println!("\n{} {}", "🔔", "Notification Rules:".cyan().bold());
                        
                        if rules.is_empty() {
                            println!("  {}", "(none)".dimmed());
                        } else {
                            for r in rules {
                                println!("\n{}", "━".repeat(80).bright_black());
                                
                                let status_badge = if r.enabled { "✓ Enabled".green() } else { "○ Disabled".red() };
                                println!("{} {} {}", status_badge.bold(), r.name.bold().bright_white(), format!("(ID: {})", r.id).dimmed());
                                
                                // Event types
                                let events_str = r.event_types.iter()
                                    .map(|e| format!("{:?}", e))
                                    .collect::<Vec<_>>()
                                    .join(", ");
                                println!("  {} {}", "Events:".dimmed(), events_str.yellow());
                                
                                // Path pattern
                                if let Some(p) = &r.path_pattern {
                                    println!("  {} {}", "Path:".dimmed(), p.cyan());
                                }
                                
                                // Action
                                let action_str = format!("{:?}", r.action_type);
                                println!("  {} {} → {}", "Action:".dimmed(), action_str.blue(), r.destination);
                                
                                // Timeout
                               println!("  {} {}s", "Timeout:".dimmed(), r.timeout.to_string().yellow());
                                
                                // Stats
                                if r.trigger_count > 0 {
                                    println!("\n  {} {}", "📊", "Stats:".bold());
                                    
                                    let success_rate = if r.trigger_count > 0 {
                                        (r.success_count as f64 / r.trigger_count as f64) * 100.0
                                    } else {
                                        0.0
                                    };
                                    
                                    let rate_color = if success_rate >= 95.0 {
                                        success_rate.to_string().green()
                                    } else if success_rate >= 80.0 {
                                        success_rate.to_string().yellow()
                                    } else {
                                        success_rate.to_string().red()
                                    };
                                    
                                    println!("    {} {} triggers", "•".dimmed(), r.trigger_count.to_string().bright_white());
                                    println!("    {} {} ({:.1}%)", "•".dimmed(), "Success".green(), success_rate);
                                    
                                    if r.failure_count > 0 {
                                        println!("    {} {} failures", "•".dimmed(), r.failure_count.to_string().red());
                                    }
                                    if r.timeout_count > 0 {
                                        println!("    {} {} timeouts", "•".dimmed(), r.timeout_count.to_string().yellow());
                                    }
                                    
                                    if r.trigger_count > 0 {
                                        let avg_ms = r.total_execution_ms as f64 / r.trigger_count as f64;
                                        println!("    {} Avg execution: {:.1}ms", "•".dimmed(), avg_ms);
                                    }
                                    
                                    if let Some(last) = r.last_triggered {
                                        let time_ago = format_time_ago(last);
                                        println!("    {} Last fired: {}", "•".dimmed(), time_ago.cyan());
                                    }
                                } else {
                                    println!("\n  {} {}", "ℹ".dimmed(), "Never triggered".dimmed());
                                }
                            }
                            println!("\n{}", "━".repeat(80).bright_black());
                        }
                        println!();
                    }
                }
                NotifyAction::Stats { rule_id } => {
                    let stats = client.get_notification_stats().await?;
                    
                    if let Some(id) = rule_id {
                        // Show stats for specific rule
                        if let Some(s) = stats.iter().find(|s| s.rule_id == id) {
                            print_rule_stats(s);
                        } else {
                            println!("{} Rule ID {} not found", "✗".red().bold(), id);
                        }
                    } else {
                        // Show all stats
                        println!("\n{} {}", "📊", "Notification Statistics:".cyan().bold());
                        
                        if stats.is_empty() {
                            println!("  {}\n", "(no rules)".dimmed());
                        } else {
                            // Summary
                            let total_triggers: u64 = stats.iter().map(|s| s.total_triggers).sum();
                            let total_success: u64 = stats.iter().map(|s| s.success_count).sum();
                            let total_failures: u64 = stats.iter().map(|s| s.failure_count).sum();
                            let total_timeouts: u64 = stats.iter().map(|s| s.timeout_count).sum();
                            
                            let overall_rate = if total_triggers > 0 {
                                (total_success as f64 / total_triggers as f64) * 100.0
                            } else {
                                0.0
                            };
                            
                            println!("\n{}", "┌─ Overall Summary ─────────────────────────────┐".bright_black());
                            println!("│ {} Total Triggers {:>27} │", "📬".dimmed(), total_triggers.to_string().bright_white());
                            println!("│ {} Successful    {:>27} │", "✓".green(), total_success.to_string().green());
                            println!("│ {} Failed        {:>27} │", "✗".red(), total_failures.to_string().red());
                            println!("│ {} Timeouts      {:>27} │", "⏱".yellow(), total_timeouts.to_string().yellow());
                            println!("│ {} Success Rate  {:>26.1}% │", "📈".dimmed(), overall_rate);
                            println!("{}\n", "└───────────────────────────────────────────────┘".bright_black());
                            
                            // Individual rule stats
                            for s in &stats {
                                print_rule_stats(s);
                            }
                        }
                    }
                }
            }
        }

        
        Commands::Interactive => {
            use std::io::{self, BufRead, Write};
            let stdin = io::stdin();
            // JSON output mode for GUI integration
            println!("{{\"status\": \"ready\"}}");
            io::stdout().flush().ok();
            
            for line in stdin.lock().lines() {
                let line = line?;
                // Split by semicolon for robust parsing
                let parts: Vec<&str> = line.trim().split(';').collect();
                if parts.is_empty() { continue; }
                
                match parts[0] {
                    "authorize" => {
                        if parts.len() < 3 {
                            println!("{{\"error\": \"usage: authorize;pattern;mode;[description]\"}}");
                            continue;
                        }
                        let pattern_str = parts[1];
                        let mode_str = parts[2];
                        let description = parts.get(3).map(|s| s.to_string());
                        
                        let pattern_list: Vec<String> = pattern_str.split(',')
                            .map(|s| s.trim().to_string())
                            .collect();

                        let match_mode = match mode_str.trim().to_lowercase().as_str() {
                            "exact" => kprotect_client::MatchMode::Exact,
                            "suffix" => kprotect_client::MatchMode::Suffix,
                            _ => {
                                println!("{{\"error\": \"invalid mode: use Exact or Suffix\"}}");
                                continue;
                            }
                        };
                        
                        // Backend Deduplication Check
                        let mut is_duplicate = false;
                        if let Ok(existing_patterns) = client.get_patterns().await {
                            for p in existing_patterns {
                                // Check if pattern content and mode match
                                if p.pattern == pattern_list && p.match_mode == match_mode {
                                    is_duplicate = true;
                                    break;
                                }
                            }
                        }
                        
                        if is_duplicate {
                           println!("{{\"status\": \"error\", \"message\": \"Pattern already authorized\"}}");
                           continue; 
                        }
                        
                        match client.authorize_pattern(&pattern_list, match_mode, description.as_deref()).await {
                            Ok(_) => println!("{{\"status\": \"ok\", \"action\": \"authorize\", \"pattern\": \"{}\"}}", pattern_str),
                            Err(e) => println!("{{\"status\": \"error\", \"message\": \"{}\"}}", e),
                        }
                    }
                    "REVOKE_PATTERN" => {
                        if parts.len() < 3 {
                            println!("{{\"error\": \"missing pattern or mode\"}}");
                            continue;
                        }
                        
                        let pattern: Vec<String> = parts[1].split(',')
                            .map(|s| s.trim().to_string())
                            .collect();
                        
                        let match_mode = match parts[2].trim() {
                            "Exact" => kprotect_common::MatchMode::Exact,
                            "Suffix" => kprotect_common::MatchMode::Suffix,
                            _ => {
                                println!("{{\"status\": \"error\", \"message\": \"invalid mode, use 'Exact' or 'Suffix'\"}}");
                                continue;
                            }
                        };
                        
                        match client.revoke_pattern(pattern.clone(), match_mode).await {
                            Ok(_) => println!("{{\"status\": \"ok\", \"action\": \"REVOKE_PATTERN\", \"pattern\": {:?}}}", pattern),
                            Err(e) => println!("{{\"status\": \"error\", \"message\": \"{}\"}}", e),
                        }
                    }
                    "list_auth" => {
                        // Fetch authorized patterns from daemon
                        match client.get_patterns().await {
                            Ok(patterns) => {
                                // Return patterns as JSON array
                                match serde_json::to_string(&patterns) {
                                    Ok(json) => println!("{}", json),
                                    Err(e) => println!("{{\"status\": \"error\", \"message\": \"Failed to serialize patterns: {}\" }}", e),
                                }
                            }
                            Err(e) => println!("{{\"status\": \"error\", \"message\": \"{}\"}}", e),
                        }
                    }
                    "zone_add" => {
                        if parts.len() < 3 {
                            println!("{{\"error\": \"usage: zone_add;type;pattern\"}}");
                            continue;
                        }
                        let zone_type = parts[1].trim();
                        let pattern = parts[2].trim();
                        
                        match client.add_zone(zone_type, pattern).await {
                             Ok(_) => println!("{{\"status\": \"ok\", \"action\": \"zone_add\", \"type\": \"{}\", \"pattern\": \"{}\"}}", zone_type, pattern),
                             Err(e) => println!("{{\"status\": \"error\", \"message\": \"{}\"}}", e),
                        }
                    }
                    "zone_remove" => {
                        if parts.len() < 3 {
                            println!("{{\"error\": \"usage: zone_remove;type;pattern\"}}");
                            continue;
                        }
                        let zone_type = parts[1].trim();
                        let pattern = parts[2].trim();
                        
                        match client.remove_zone(zone_type, pattern).await {
                             Ok(_) => println!("{{\"status\": \"ok\", \"action\": \"zone_remove\", \"type\": \"{}\", \"pattern\": \"{}\"}}", zone_type, pattern),
                             Err(e) => println!("{{\"status\": \"error\", \"message\": \"{}\"}}", e),
                        }
                    }
                    "zone_list" => {
                        match client.list_zones().await {
                            Ok(zones) => {
                                match serde_json::to_string(&zones) {
                                    Ok(json) => println!("{}", json),
                                    Err(e) => println!("{{\"status\": \"error\", \"message\": \"Failed to serialize zones: {}\"}}", e),
                                }
                            }
                            Err(e) => println!("{{\"status\": \"error\", \"message\": \"{}\"}}", e),
                        }
                    }
                    "pattern_add" => {
                        if parts.len() < 2 {
                            println!("{{\"error\": \"usage: pattern_add;pattern\"}}");
                            continue;
                        }
                        let pattern = parts[1].trim();
                        
                        match client.add_enrichment_pattern(pattern).await {
                             Ok(_) => println!("{{\"status\": \"ok\", \"action\": \"pattern_add\", \"pattern\": \"{}\"}}", pattern),
                             Err(e) => println!("{{\"status\": \"error\", \"message\": \"{}\"}}", e),
                        }
                    }
                    "pattern_remove" => {
                        if parts.len() < 2 {
                            println!("{{\"error\": \"usage: pattern_remove;pattern\"}}");
                            continue;
                        }
                        let pattern = parts[1].trim();
                        
                        match client.remove_enrichment_pattern(pattern).await {
                             Ok(_) => println!("{{\"status\": \"ok\", \"action\": \"pattern_remove\", \"pattern\": \"{}\"}}", pattern),
                             Err(e) => println!("{{\"status\": \"error\", \"message\": \"{}\"}}", e),
                        }
                    }
                    "pattern_list" => {
                        match client.list_enrichment_patterns().await {
                            Ok(config) => {
                                match serde_json::to_string(&config) {
                                    Ok(json) => println!("{}", json),
                                    Err(e) => println!("{{\"status\": \"error\", \"message\": \"Failed to serialize patterns: {}\"}}", e),
                                }
                            }
                            Err(e) => println!("{{\"status\": \"error\", \"message\": \"{}\"}}", e),
                        }
                    }
                    "ping" => println!("{{\"status\": \"pong\"}}"),
                    "status" => {
                        let status = client.get_daemon_status().await.ok();
                        let encryption = client.get_encryption_info().await.ok();
                        let system = client.get_system_info().await.ok();
                        
                        let output = serde_json::json!({
                            "status": "ok",
                            "daemon": status,
                            "encryption": encryption,
                            "system": system
                        });
                        println!("{}", output.to_string());
                    }
                    "get_log_config" => {
                        match client.get_log_config().await {
                            Ok(config) => {
                                match serde_json::to_string(&config) {
                                    Ok(json) => println!("{}", json),
                                    Err(e) => println!("{{\"status\": \"error\", \"message\": \"{}\"}}", e),
                                }
                            }
                            Err(e) => println!("{{\"status\": \"error\", \"message\": \"{}\"}}", e),
                        }
                    }
                    "set_log_retention" => {
                        if parts.len() < 3 {
                            println!("{{\"error\": \"usage: set_log_retention;events;audit\"}}");
                            continue;
                        }
                        let events = parts[1].trim().parse::<u32>().unwrap_or(30);
                        let audit = parts[2].trim().parse::<u32>().unwrap_or(90);
                        match client.set_log_retention(events, audit).await {
                            Ok(_) => println!("{{\"status\": \"ok\", \"action\": \"set_log_retention\"}}"),
                            Err(e) => println!("{{\"status\": \"error\", \"message\": \"{}\"}}", e),
                        }
                    }
                    "get_audit" => {
                        let count = parts.get(1).and_then(|c| c.trim().parse::<usize>().ok()).unwrap_or(50);
                        match client.get_audit(count, 0).await {
                            Ok(logs) => {
                                match serde_json::to_string(&logs) {
                                    Ok(json) => println!("{}", json),
                                    Err(e) => println!("{{\"status\": \"error\", \"message\": \"{}\"}}", e),
                                }
                            }
                            Err(e) => println!("{{\"status\": \"error\", \"message\": \"{}\"}}", e),
                        }
                    }
                    "notify_add" => {
                        if parts.len() < 7 {
                            println!("{{\"error\": \"usage: notify_add;name;events;path;action;dest;timeout\"}}");
                            continue;
                        }
                        let name = parts[1];
                        let events: Vec<kprotect_common::EventTypeFilter> = parts[2].split(',')
                            .map(|s| match s.trim() {
                                "Verified" => kprotect_common::EventTypeFilter::Verified,
                                "Blocked" => kprotect_common::EventTypeFilter::Blocked,
                                _ => kprotect_common::EventTypeFilter::Blocked,
                            })
                            .collect();
                        let path = if parts[3].is_empty() || parts[3] == "null" { None } else { Some(parts[3]) };
                        let action = match parts[4].to_lowercase().as_str() {
                            "script" => kprotect_common::ActionType::Script,
                            _ => kprotect_common::ActionType::Webhook,
                        };
                        let dest = parts[5];
                        let timeout = parts[6].parse::<u32>().unwrap_or(30);

                        match client.add_notification_rule(name, &events, path, action, dest, timeout).await {
                             Ok(_) => println!("{{\"status\": \"ok\", \"action\": \"notify_add\", \"name\": \"{}\"}}", name),
                             Err(e) => println!("{{\"status\": \"error\", \"message\": \"{}\"}}", e),
                        }
                    }
                    "notify_remove" => {
                        if parts.len() < 2 {
                            println!("{{\"error\": \"usage: notify_remove;id\"}}");
                            continue;
                        }
                        if let Ok(id) = parts[1].trim().parse::<u32>() {
                            match client.remove_notification_rule(id).await {
                                Ok(_) => println!("{{\"status\": \"ok\", \"action\": \"notify_remove\", \"id\": {}}}", id),
                                Err(e) => println!("{{\"status\": \"error\", \"message\": \"{}\"}}", e),
                            }
                        }
                    }
                    "notify_list" => {
                        match client.get_notification_rules().await {
                            Ok(rules) => {
                                match serde_json::to_string(&rules) {
                                    Ok(json) => println!("{}", json),
                                    Err(e) => println!("{{\"status\": \"error\", \"message\": \"{}\"}}", e),
                                }
                            }
                            Err(e) => println!("{{\"status\": \"error\", \"message\": \"{}\"}}", e),
                        }
                    }
                    "notify_toggle" => {
                        if parts.len() < 3 {
                            println!("{{\"error\": \"usage: notify_toggle;id;enabled\"}}");
                            continue;
                        }
                        if let (Ok(id), Ok(enabled)) = (parts[1].trim().parse::<u32>(), parts[2].trim().parse::<bool>()) {
                            match client.toggle_notification_rule(id, enabled).await {
                                Ok(_) => println!("{{\"status\": \"ok\", \"action\": \"notify_toggle\", \"id\": {}, \"enabled\": {}}}", id, enabled),
                                Err(e) => println!("{{\"status\": \"error\", \"message\": \"{}\"}}", e),
                            }
                        }
                    }
                    "GET_STATS" => {
                        match client.get_stats().await {
                            Ok(stats) => {
                                match serde_json::to_string(&stats) {
                                    Ok(json) => println!("{}", json),
                                    Err(e) => println!("{{\"status\": \"error\", \"message\": \"Failed to serialize stats: {}\"}}", e),
                                }
                            }
                            Err(e) => println!("{{\"status\": \"error\", \"message\": \"{}\"}}", e),
                        }
                    }
                    "exit" | "quit" => break,
                    _ => println!("{{\"status\": \"error\", \"message\": \"unknown command\"}}"),
                }
            }
        }
    }
    
    Ok(())
}

/// Format a Unix timestamp as "time ago" string
fn format_time_ago(timestamp: u64) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    if timestamp > now {
        return "in the future".to_string();
    }
    
    let diff = now - timestamp;
    
    if diff < 60 {
        format!("{}s ago", diff)
    } else if diff < 3600 {
        format!("{}m ago", diff / 60)
    } else if diff < 86400 {
        format!("{}h ago", diff / 3600)
    } else {
        format!("{}d ago", diff / 86400)
    }
}

/// Print stats for a single notification rule
fn print_rule_stats(s: &kprotect_common::NotificationStats) {
    use colored::*;
    
    println!("\n{}", "┌────────────────────────────────────────────────┐".bright_black());
    println!("│ {} {} {}", 
        "Rule:".dimmed(), 
        s.rule_name.bold().bright_white(),
        format!("(ID: {})", s.rule_id).dimmed()
    );
    println!("{}", "├────────────────────────────────────────────────┤".bright_black());
    
    if s.total_triggers == 0 {
        println!("│ {} {}                                   │", "ℹ".dimmed(), "Never triggered".dimmed());
    } else {
        println!("│ {} Triggers:     {:>27} │", "📬".dimmed(), s.total_triggers.to_string().bright_white());
        println!("│ {} Success:      {:>27} │", "✓".green(), s.success_count.to_string().green());
        
        if s.failure_count > 0 {
            println!("│ {} Failed:       {:>27} │", "✗".red(), s.failure_count.to_string().red());
        }
        if s.timeout_count > 0 {
            println!("│ {} Timeouts:     {:>27} │", "⏱".yellow(), s.timeout_count.to_string().yellow());
        }
        
        let rate_colored = if s.success_rate >= 95.0 {
            format!("{:.1}%", s.success_rate).green()
        } else if s.success_rate >= 80.0 {
            format!("{:.1}%", s.success_rate).yellow()
        } else {
            format!("{:.1}%", s.success_rate).red()
        };
        
        println!("│ {} Success Rate: {:>27} │", "📈".dimmed(), rate_colored.to_string());
        println!("│ {} Avg Time:     {:>24.1}ms │", "⚡".dimmed(), s.avg_execution_ms);
        
        if let Some(last) = s.last_triggered {
            let time_ago = format_time_ago(last);
            println!("│ {} Last Fired:   {:>27} │", "🕐".dimmed(), time_ago.cyan().to_string());
        }
    }
    
    println!("{}", "└────────────────────────────────────────────────┘".bright_black());
}

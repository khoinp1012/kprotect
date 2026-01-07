use chrono::{DateTime, Local};
use kprotect_client::KprotectClient;

// Re-export types from kprotect_client
pub use kprotect_client::{
    DaemonStatus,
    EncryptionInfo,
    SystemInfo,
    LogConfig,
    ZonesConfig,
};

// Re-export types from kprotect_common
pub use kprotect_common::{
    AuthorizedPattern,
    NotificationRule,
    LogEntry,
};

// Custom AuditLog type for display purposes
#[derive(Debug, Clone)]
pub struct AuditLog {
    pub timestamp: u64,
    pub action: String,
    pub username: String,
    pub details: String,
    pub success: bool,
}

/// Application state
pub struct App {
    pub current_panel: Panel,
    pub selected_index: usize,
    pub events: Vec<Event>,
    pub statistics: Statistics,
    pub connection_status: ConnectionStatus,
    pub should_quit: bool,
    pub show_help: bool,
    pub client: Option<KprotectClient>,
    pub socket_path: String,
    pub status_message: Option<StatusMessage>,
    
    pub daemon_status: Option<DaemonStatus>,
    pub encryption_info: Option<EncryptionInfo>,
    pub system_info: Option<SystemInfo>,
    
    // Notifications data
    pub notification_rules: Vec<NotificationRule>,
    
    // Settings data
    pub log_config: Option<LogConfig>,
    pub audit_logs: Vec<AuditLog>,
    
    // Zones and patterns
    pub zones_config: Option<ZonesConfig>,
    pub enrichment_patterns: Vec<String>,
    pub authorized_patterns: Vec<AuthorizedPattern>,
}

#[derive(Debug, Clone)]
pub struct StatusMessage {
    pub text: String,
    pub is_error: bool,
    pub timestamp: DateTime<Local>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Panel {
    Dashboard,
    Events,
    AuthorizedSignatures,
    Zones,
    Enrichment,
    Notifications,
    Settings,
}

impl Panel {
    pub fn name(&self) -> &str {
        match self {
            Panel::Dashboard => "Dashboard",
            Panel::Events => "Live Events",
            Panel::AuthorizedSignatures => "Authorized Signatures",
            Panel::Zones => "Security Zones",
            Panel::Enrichment => "Enrichment Patterns",
            Panel::Notifications => "Notifications",
            Panel::Settings => "Settings",
        }
    }
    
    pub fn shortcut(&self) -> &str {
        match self {
            Panel::Dashboard => "Alt+1",
            Panel::Events => "Alt+2",
            Panel::AuthorizedSignatures => "Alt+3",
            Panel::Zones => "Alt+4",
            Panel::Enrichment => "Alt+5",
            Panel::Notifications => "Alt+6",
            Panel::Settings => "Alt+7",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Event {
    pub timestamp: DateTime<Local>,
    pub event_type: EventType,
    pub pid: u32,
    pub signature: String,
    pub path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    Verified,
    Block,
}

impl EventType {
    pub fn as_str(&self) -> &str {
        match self {
            EventType::Verified => "VERIFIED",
            EventType::Block => "BLOCK",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Statistics {
    pub total: usize,
    pub verified: usize,
    pub block: usize,
}

impl Statistics {
    pub fn new() -> Self {
        Self {
            total: 0,
            verified: 0,
            block: 0,
        }
    }
    
    pub fn update_from_events(events: &[Event]) -> Self {
        let mut stats = Self::new();
        stats.total = events.len();
        
        for event in events {
            match event.event_type {
                EventType::Verified => stats.verified += 1,
                EventType::Block => stats.block += 1,
            }
        }
        
        stats
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionStatus {
    Connected,
    Disconnected,
    Connecting,
}

impl ConnectionStatus {
    pub fn as_str(&self) -> &str {
        match self {
            ConnectionStatus::Connected => "Connected",
            ConnectionStatus::Disconnected => "Disconnected",
            ConnectionStatus::Connecting => "Connecting...",
        }
    }
}

impl App {
    pub fn new() -> Self {
        let socket_path = "/run/kprotect/kprotect.sock".to_string();
        
        Self {
            current_panel: Panel::Dashboard,
            selected_index: 0,
            events: Vec::new(), // Start empty, will be populated by live stream
            statistics: Statistics::new(),
            connection_status: ConnectionStatus::Disconnected,
            should_quit: false,
            show_help: false,
            client: None,
            socket_path,
            status_message: None,
            
            // Dashboard data
            daemon_status: None,
            encryption_info: None,
            system_info: None,
            
            // Notifications data
            notification_rules: Vec::new(),
            
            // Settings data
            log_config: None,
            audit_logs: Vec::new(),
            
            // Zones and patterns
            zones_config: None,
            enrichment_patterns: Vec::new(),
            authorized_patterns: Vec::new(),
        }
    }
    
    /// Add a new event from the daemon stream
    pub fn add_event(&mut self, event: Event) {
        // Add to front (most recent first)
        self.events.insert(0, event);
        
        // Limit to last 1000 events
        if self.events.len() > 1000 {
            self.events.truncate(1000);
        }
        
        // Update statistics
        self.update_statistics();
    }
    
    pub async fn connect_to_daemon(&mut self) {
        self.connection_status = ConnectionStatus::Connecting;
        
        let client = KprotectClient::with_socket_path(&self.socket_path);
        
        // Try to ping daemon
        match client.ping().await {
            Ok(_) => {
                self.client = Some(client);
                self.connection_status = ConnectionStatus::Connected;
                self.set_status("Connected to daemon", false);
            }
            Err(e) => {
                self.connection_status = ConnectionStatus::Disconnected;
                self.set_status(&format!("Failed to connect: {}", e), true);
            }
        }
    }
    
    pub fn set_status(&mut self, text: &str, is_error: bool) {
        self.status_message = Some(StatusMessage {
            text: text.to_string(),
            is_error,
            timestamp: Local::now(),
        });
    }
    
    pub fn clear_status(&mut self) {
        self.status_message = None;
    }
    
    pub async fn authorize_selected(&mut self) {
        if let Some(event) = self.get_selected_event() {
            if event.event_type != EventType::Block {
                self.set_status("Can only authorize BLOCK signatures", true);
                return;
            }
            
            if let Some(client) = &self.client {
                let sig_str = event.signature.trim_start_matches("0x");
                match u64::from_str_radix(sig_str, 16) {
                    Ok(sig) => {
                        match client.authorize(sig, Some(&format!("Authorized from TUI: {}", event.path))).await {
                            Ok(_) => {
                                self.set_status(&format!("✓ Authorized: {}", event.signature), false);
                            }
                            Err(e) => {
                                self.set_status(&format!("✗ Failed to authorize: {}", e), true);
                            }
                        }
                    }
                    Err(_) => {
                        self.set_status("Invalid signature format", true);
                    }
                }
            } else {
                self.set_status("Not connected to daemon", true);
            }
        }
    }
    
    pub async fn revoke_selected(&mut self) {
        if let Some(event) = self.get_selected_event() {
            if let Some(client) = &self.client {
                let sig_str = event.signature.trim_start_matches("0x");
                match u64::from_str_radix(sig_str, 16) {
                    Ok(sig) => {
                        match client.revoke(sig).await {
                            Ok(_) => {
                                self.set_status(&format!("✓ Revoked: {}", event.signature), false);
                            }
                            Err(e) => {
                                self.set_status(&format!("✗ Failed to revoke: {}", e), true);
                            }
                        }
                    }
                    Err(_) => {
                        self.set_status("Invalid signature format", true);
                    }
                }
            } else {
                self.set_status("Not connected to daemon", true);
            }
        }
    }
    
    pub fn switch_panel(&mut self, panel: Panel) {
        self.current_panel = panel;
        self.selected_index = 0; // Reset selection when switching panels
    }
    
    pub fn select_next(&mut self) {
        if self.events.is_empty() {
            return;
        }
        if self.selected_index < self.events.len() - 1 {
            self.selected_index += 1;
        }
    }
    
    pub fn select_previous(&mut self) {
        self.selected_index = self.selected_index.saturating_sub(1);
    }
    
    pub fn toggle_help(&mut self) {
        self.show_help = !self.show_help;
    }
    
    pub fn update_statistics(&mut self) {
        self.statistics = Statistics::update_from_events(&self.events);
    }
    
    pub fn clear_events(&mut self) {
        self.events.clear();
        self.selected_index = 0;
        self.update_statistics();
    }
    
    pub fn get_selected_event(&self) -> Option<&Event> {
        self.events.get(self.selected_index)
    }
    
    /// Fetch dashboard data from daemon
    pub async fn fetch_dashboard_data(&mut self) {
        if let Some(client) = &self.client {
            // Fetch all dashboard data concurrently
            if let Ok(status) = client.get_daemon_status().await {
                self.daemon_status = Some(status);
            }
            
            if let Ok(encryption) = client.get_encryption_info().await {
                self.encryption_info = Some(encryption);
            }
            
            if let Ok(info) = client.get_system_info().await {
                self.system_info = Some(info);
            }
        }
    }
    
    /// Fetch notification rules
    pub async fn fetch_notification_rules(&mut self) {
        if let Some(client) = &self.client {
            if let Ok(rules) = client.get_notification_rules().await {
                self.notification_rules = rules;
            }
        }
    }
    
    /// Fetch settings data
    pub async fn fetch_settings_data(&mut self) {
        if let Some(client) = &self.client {
            if let Ok(config) = client.get_log_config().await {
                self.log_config = Some(config);
            }
            
            // Fetch audit logs and extract from LogEntry enum
            if let Ok(logs) = client.get_audit(50, 0).await {
                self.audit_logs = logs.into_iter().filter_map(|log| {
                    match log {
                        LogEntry::AuditAction { timestamp, action, username, details, success } => {
                            Some(AuditLog {
                                timestamp,
                                action,
                                username,
                                details: serde_json::to_string(&details).unwrap_or_default(),
                                success,
                            })
                        },
                        _ => None,
                    }
                }).collect();
            }
        }
    }
    
    /// Fetch zones config
    pub async fn fetch_zones(&mut self) {
        if let Some(client) = &self.client {
            if let Ok(zones) = client.list_zones().await {
                self.zones_config = Some(zones);
            }
        }
    }
    
    /// Fetch enrichment patterns
    pub async fn fetch_enrichment_patterns(&mut self) {
        if let Some(client) = &self.client {
            if let Ok(config) = client.list_enrichment_patterns().await {
                self.enrichment_patterns = config.enrichment_patterns;
            }
        }
    }
    
    /// Fetch authorized patterns
    pub async fn fetch_authorized_patterns(&mut self) {
        if let Some(client) = &self.client {
            if let Ok(patterns) = client.get_patterns().await {
                self.authorized_patterns = patterns;
            }
        }
    }
    
    /// Refresh all panel data based on current panel
    pub async fn refresh_current_panel_data(&mut self) {
        match self.current_panel {
            Panel::Dashboard => self.fetch_dashboard_data().await,
            Panel::Notifications => self.fetch_notification_rules().await,
            Panel::Settings => self.fetch_settings_data().await,
            Panel::Zones => self.fetch_zones().await,
            Panel::Enrichment => self.fetch_enrichment_patterns().await,
            Panel::AuthorizedSignatures => self.fetch_authorized_patterns().await,
            Panel::Events => {}, // Events are streamed live
        }
    }
}

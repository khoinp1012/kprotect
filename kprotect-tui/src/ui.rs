use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
    Frame,
};

use crate::app::{App, ConnectionStatus, EventType, Panel};

pub fn render(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Length(3), // Statistics
            Constraint::Length(3), // Panel selector
            Constraint::Min(0),    // Main content
            Constraint::Length(3), // Footer
            Constraint::Length(if app.status_message.is_some() { 2 } else { 0 }), // Status message
        ])
        .split(f.size());
    
    render_header(f, chunks[0], app);
    render_statistics(f, chunks[1], app);
    render_panel_selector(f, chunks[2], app);
    render_main_content(f, chunks[3], app);
    render_footer(f, chunks[4], app);
    
    if let Some(status) = &app.status_message {
        render_status_message(f, chunks[5], status);
    }
    
    if app.show_help {
        render_help_dialog(f, app);
    }
}

fn render_header(f: &mut Frame, area: Rect, app: &App) {
    let connection_color = match app.connection_status {
        ConnectionStatus::Connected => Color::Green,
        ConnectionStatus::Disconnected => Color::Red,
        ConnectionStatus::Connecting => Color::Yellow,
    };
    
    let text = vec![Line::from(vec![
        Span::styled("kprotect", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw(" Monitor  |  "),
        Span::styled(app.connection_status.as_str(), Style::default().fg(connection_color)),
        Span::raw("  |  Panel: "),
        Span::styled(app.current_panel.name(), Style::default().fg(Color::Yellow)),
    ])];
    
    let paragraph = Paragraph::new(text)
        .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::Cyan)))
        .alignment(Alignment::Center);
    
    f.render_widget(paragraph, area);
}

fn render_statistics(f: &mut Frame, area: Rect, app: &App) {
    let stats = &app.statistics;
    
    let text = vec![Line::from(vec![
        Span::raw("  Total: "),
        Span::styled(stats.total.to_string(), Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        Span::raw("  |  ✓ Verified: "),
        Span::styled(stats.verified.to_string(), Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::raw("  |  ✗ Block: "),
        Span::styled(stats.block.to_string(), Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
    ])];
    
    let paragraph = Paragraph::new(text)
        .block(Block::default().borders(Borders::ALL).title("Statistics"))
        .alignment(Alignment::Left);
    
    f.render_widget(paragraph, area);
}

fn render_panel_selector(f: &mut Frame, area: Rect, app: &App) {
    let panels = [
        ("1", "Dashboard"),
        ("2", "Events"),
        ("3", "Authorized"),
        ("4", "Zones"),
        ("5", "Enrichment"),
        ("6", "Notifications"),
        ("7", "Settings"),
    ];
    
    let panel_index = match app.current_panel {
        Panel::Dashboard => 0,
        Panel::Events => 1,
        Panel::AuthorizedSignatures => 2,
        Panel::Zones => 3,
        Panel::Enrichment => 4,
        Panel::Notifications => 5,
        Panel::Settings => 6,
    };
    
    let mut spans = vec![Span::raw("  ")];
    for (i, (num, name)) in panels.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw(" │ "));
        }
        
        let style = if i == panel_index {
            Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Gray)
        };
        
        spans.push(Span::styled(format!("{} {}", num, name), style));
    }
    
    let text = vec![Line::from(spans)];
    
    let paragraph = Paragraph::new(text)
        .block(Block::default().borders(Borders::ALL).title("Panels"))
        .alignment(Alignment::Left);
    
    f.render_widget(paragraph, area);
}

fn render_main_content(f: &mut Frame, area: Rect, app: &App) {
    match app.current_panel {
        Panel::Dashboard => render_dashboard_panel(f, area, app),
        Panel::Events => render_events_panel(f, area, app),
        Panel::AuthorizedSignatures => render_authorized_patterns_panel(f, area, app),
        Panel::Zones => render_zones_panel(f, area, app),
        Panel::Enrichment => render_enrichment_panel(f, area, app),
        Panel::Notifications => render_notifications_panel(f, area, app),
        Panel::Settings => render_settings_panel(f, area, app),
    }
}

fn render_events_panel(f: &mut Frame, area: Rect, app: &App) {
    let header_cells = ["Time", "Type", "PID", "Signature", "Path"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));
    let header = Row::new(header_cells).height(1).bottom_margin(1);
    
    let rows = app.events.iter().enumerate().map(|(i, event)| {
        let type_color = match event.event_type {
            EventType::Verified => Color::Green,
            EventType::Block => Color::Red,
        };
        
        let cells = vec![
            Cell::from(event.timestamp.format("%H:%M:%S").to_string()),
            Cell::from(event.event_type.as_str()).style(Style::default().fg(type_color).add_modifier(Modifier::BOLD)),
            Cell::from(event.pid.to_string()),
            Cell::from(event.signature.clone()),
            Cell::from(event.path.clone()),
        ];
        
        let style = if i == app.selected_index {
            Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        
        Row::new(cells).height(1).style(style)
    });
    
    let widths = [
        Constraint::Length(10), // Time
        Constraint::Length(10), // Type
        Constraint::Length(8),  // PID
        Constraint::Length(18), // Signature
        Constraint::Min(20),    // Path
    ];
    
    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title("Events (Live)"))
        .highlight_style(Style::default().bg(Color::DarkGray));
    
    f.render_widget(table, area);
}

fn render_status_message(f: &mut Frame, area: Rect, status: &crate::app::StatusMessage) {
    let color = if status.is_error {
        Color::Red
    } else {
        Color::Green
    };
    
    let text = vec![Line::from(Span::styled(
        format!("  {} (ESC to clear)", status.text),
        Style::default().fg(color).add_modifier(Modifier::BOLD),
    ))];
    
    let paragraph = Paragraph::new(text).alignment(Alignment::Left);
    f.render_widget(paragraph, area);
}

fn render_placeholder(f: &mut Frame, area: Rect, title: &str, message: &str) {
    let text = vec![
        Line::from(""),
        Line::from(Span::styled(message, Style::default().fg(Color::Gray))),
    ];
    
    let paragraph = Paragraph::new(text)
        .block(Block::default().borders(Borders::ALL).title(title))
        .alignment(Alignment::Center);
    
    f.render_widget(paragraph, area);
}

fn render_footer(f: &mut Frame, area: Rect, app: &App) {
    let shortcuts = match app.current_panel {
        Panel::Events => vec![
            ("↑↓", "Select"),
            ("A", "Authorize"),
            ("X", "Revoke"),
            ("C", "Clear"),
        ],
        _ => vec![
            ("↑↓", "Navigate"),
        ],
    };
    
    let mut spans = vec![Span::raw("  ")];
    for (i, (key, desc)) in shortcuts.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw("  |  "));
        }
        spans.push(Span::styled(*key, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)));
        spans.push(Span::raw(": "));
        spans.push(Span::raw(*desc));
    }
    
    spans.push(Span::raw("  |  "));
    spans.push(Span::styled("Alt+1-7", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));
    spans.push(Span::raw(": Switch Panel  |  "));
    
    // Add panel indicator
    let panel_num = match app.current_panel {
        Panel::Dashboard => 1,
        Panel::Events => 2,
        Panel::AuthorizedSignatures => 3,
        Panel::Zones => 4,
        Panel::Enrichment => 5,
        Panel::Notifications => 6,
        Panel::Settings => 7,
    };
    spans.push(Span::styled(format!("[{}/7]", panel_num), Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)));
    spans.push(Span::raw("  |  "));
    
    spans.push(Span::styled("?", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)));
    spans.push(Span::raw(": Help  |  "));
    spans.push(Span::styled("ESC", Style::default().fg(Color::Gray).add_modifier(Modifier::BOLD)));
    spans.push(Span::raw(": Clear Status  |  "));
    spans.push(Span::styled("Q", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)));
    spans.push(Span::raw(": Quit"));
    
    let text = vec![Line::from(spans)];
    
    let paragraph = Paragraph::new(text)
        .block(Block::default().borders(Borders::ALL))
        .alignment(Alignment::Left);
    
    f.render_widget(paragraph, area);
}

fn render_help_dialog(f: &mut Frame, _app: &App) {
    let area = centered_rect(60, 70, f.size());
    
    let help_text = vec![
        Line::from(""),
        Line::from(Span::styled("Keyboard Shortcuts", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))),
        Line::from(""),
        Line::from(vec![
            Span::styled("Alt+1", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw("          Switch to Dashboard"),
        ]),
        Line::from(vec![
            Span::styled("Alt+2", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw("          Switch to Events"),
        ]),
        Line::from(vec![
            Span::styled("Alt+3", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw("          Switch to Authorized Signatures"),
        ]),
        Line::from(vec![
            Span::styled("Alt+4", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw("          Switch to Zones"),
        ]),
        Line::from(vec![
            Span::styled("Alt+5", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw("          Switch to Enrichment"),
        ]),
        Line::from(vec![
            Span::styled("Alt+6", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw("          Switch to Notifications"),
        ]),
        Line::from(vec![
            Span::styled("Alt+7", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw("          Switch to Settings"),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("↑ / ↓", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw("          Navigate rows"),
        ]),
        Line::from(vec![
            Span::styled("A", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
            Span::raw("              Authorize selected signature"),
        ]),
        Line::from(vec![
            Span::styled("X", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
            Span::raw("              Revoke selected signature"),
        ]),
        Line::from(vec![
            Span::styled("C", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::raw("              Clear events"),
        ]),
        Line::from(vec![
            Span::styled("?", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw("              Toggle this help"),
        ]),
        Line::from(vec![
            Span::styled("Q", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
            Span::raw("              Quit"),
        ]),
        Line::from(""),
        Line::from(Span::styled("Press ? to close", Style::default().fg(Color::Gray))),
    ];
    
    let paragraph = Paragraph::new(help_text)
        .block(Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow))
            .title("Help"))
        .alignment(Alignment::Left);
    
    f.render_widget(ratatui::widgets::Clear, area);
    f.render_widget(paragraph, area);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);
    
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

// =====================================================
// New Panel Rendering Functions  
// =====================================================

fn render_dashboard_panel(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(10), // Status cards
            Constraint::Min(0),      // Resource usage
        ])
        .split(area);
    
    // Top section: Status cards
    let status_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(33), Constraint::Percentage(33), Constraint::Percentage(34)])
        .split(chunks[0]);
    
    // Daemon Status Card
    let daemon_info = if let Some(status) = &app.daemon_status {
        vec![
            Line::from(Span::styled(format!("Uptime: {}s", status.uptime_seconds), Style::default().fg(Color::White))),
            Line::from(Span::styled(format!("eBPF: {}", if status.ebpf_loaded { "✓ Loaded" } else { "✗ Not Loaded" }), 
                Style::default().fg(if status.ebpf_loaded { Color::Green } else { Color::Red }))),
            Line::from(Span::styled(format!("Connections: {}", status.active_connections), Style::default().fg(Color::Cyan))),
        ]
    } else {
        vec![Line::from(Span::styled("Loading...", Style::default().fg(Color::Gray)))]
    };
    
    let daemon_widget = Paragraph::new(daemon_info)
        .block(Block::default().borders(Borders::ALL).title("Daemon Status").border_style(Style::default().fg(Color::Cyan)))
        .alignment(Alignment::Left);
    f.render_widget(daemon_widget,status_chunks[0]);
    
    // Security Card
    let security_info = if let Some(enc) = &app.encryption_info {
        vec![
            Line::from(Span::styled(format!("Encryption: {}", if enc.enabled { "✓ Enabled" } else { "✗ Disabled" }), 
                Style::default().fg(if enc.enabled { Color::Green } else { Color::Yellow }))),
            Line::from(Span::styled(format!("Algorithm: {}", enc.algorithm), Style::default().fg(Color::White))),
            Line::from(Span::styled(format!("Key: {}...", &enc.key_fingerprint[..12.min(enc.key_fingerprint.len())]), Style::default().fg(Color::Gray))),
        ]
    } else {
        vec![Line::from(Span::styled("Loading...", Style::default().fg(Color::Gray)))]
    };
    
    let security_widget = Paragraph::new(security_info)
        .block(Block::default().borders(Borders::ALL).title("Security").border_style(Style::default().fg(Color::Green)))
        .alignment(Alignment::Left);
    f.render_widget(security_widget, status_chunks[1]);
    
    // Activity Card
    let activity_info = if let Some(sys) = &app.system_info {
        vec![
            Line::from(Span::styled(format!("✓ Verified: {}", sys.events_verified), Style::default().fg(Color::Green))),
            Line::from(Span::styled(format!("✗ Blocked: {}", sys.events_blocked), Style::default().fg(Color::Red))),
            Line::from(Span::styled(format!("Policies: {}", sys.authorized_patterns), Style::default().fg(Color::Cyan))),
        ]
    } else {
        vec![Line::from(Span::styled("Loading...", Style::default().fg(Color::Gray)))]
    };
    
    let activity_widget = Paragraph::new(activity_info)
        .block(Block::default().borders(Borders::ALL).title("Activity Overview").border_style(Style::default().fg(Color::Blue)))
        .alignment(Alignment::Left);
    f.render_widget(activity_widget, status_chunks[2]);
    
    // Bottom section: Resource table
    let mut resource_rows = vec![];
    if let Some(sys) = &app.system_info {
        // Add lineage cache
        resource_rows.push(Row::new(vec![
            Cell::from("Lineage Cache"),
            Cell::from(format!("{}", sys.lineage_cache_size)),
            Cell::from("10000"),
            Cell::from(format!("{:.1}%", (sys.lineage_cache_size as f64 / 10000.0) * 100.0)),
        ]));
        
        // Add eBPF maps
        for (name, stats) in &sys.ebpf_maps {
            if name != "authorized_signatures" {
                resource_rows.push(Row::new(vec![
                    Cell::from(name.clone()),
                    Cell::from(format!("{}", stats.size)),
                    Cell::from(format!("{}", stats.capacity)),
                    Cell::from(format!("{:.1}%", (stats.size as f64 / stats.capacity as f64) * 100.0)),
                ]));
            }
        }
    }
    
    let resource_table = Table::new(resource_rows, [
        Constraint::Percentage(40),
        Constraint::Percentage(20),
        Constraint::Percentage(20),
        Constraint::Percentage(20),
    ])
    .header(Row::new(vec!["Resource", "Size", "Capacity", "Usage"]).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)))
    .block(Block::default().borders(Borders::ALL).title("Resource Usage"));
    
    f.render_widget(resource_table, chunks[1]);
}

fn render_notifications_panel(f: &mut Frame, area: Rect, app: &App) {
    if app.notification_rules.is_empty() {
        render_placeholder(f, area, "Notification Rules", "No notification rules configured");
        return;
    }
    
    let header_cells = ["ID", "Name", "Type", "Events", "Status", "Triggers"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));
    let header = Row::new(header_cells).height(1).bottom_margin(1);
    
    let rows = app.notification_rules.iter().map(|rule| {
        let status_color = if rule.enabled { Color::Green } else { Color::Gray };
        let status_text = if rule.enabled { "✓ Enabled" } else { "✗ Disabled" };
        
        // Convert enums to strings
        let action_str = format!("{:?}", rule.action_type);
        let events_str = rule.event_types.iter()
            .map(|et| format!("{:?}", et))
            .collect::<Vec<_>>()
            .join(",");
        
        let cells = vec![
            Cell::from(format!("{}", rule.id)),
            Cell::from(rule.name.clone()),
            Cell::from(action_str),
            Cell::from(events_str),
            Cell::from(status_text).style(Style::default().fg(status_color)),
            Cell::from(format!("{}", rule.trigger_count)),
        ];
        
        Row::new(cells).height(1)
    });
    
    let table = Table::new(rows, [
        Constraint::Length(5),
        Constraint::Min(15),
        Constraint::Length(10),
        Constraint::Length(15),
        Constraint::Length(12),
        Constraint::Length(10),
    ])
    .header(header)
    .block(Block::default().borders(Borders::ALL).title("Notification Rules"));
    
    f.render_widget(table, area);
}

fn render_settings_panel(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(8),  // Retention info
            Constraint::Min(0),     // Audit logs
        ])
        .split(area);
    
    // Retention info
    let retention_info = if let Some(config) = &app.log_config {
        vec![
            Line::from(""),
            Line::from(vec![
                Span::raw("Security Events Retention: "),
                Span::styled(format!("{} days", config.event_log_retention_days), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(vec![
                Span::raw("Audit Log Retention: "),
                Span::styled(format!("{} days", config.audit_log_retention_days), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(""),
            Line::from(Span::styled("Note: Retention settings require root access to modify", Style::default().fg(Color::Gray))),
        ]
    } else {
        vec![Line::from(""), Line::from(Span::styled("Loading configuration...", Style::default().fg(Color::Gray)))]
    };
    
    let retention_widget = Paragraph::new(retention_info)
        .block(Block::default().borders(Borders::ALL).title("Log Retention Configuration"))
        .alignment(Alignment::Left);
    f.render_widget(retention_widget, chunks[0]);
    
    // Audit logs table
    let header_cells = ["Time", "User", "Action", "Status"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));
    let header = Row::new(header_cells).height(1).bottom_margin(1);
    
    let rows = app.audit_logs.iter().map(|log| {
        let status_color = if log.success { Color::Green } else { Color::Red };
        let status_text = if log.success { "✓ Success" } else { "✗ Failed" };
        
        let timestamp_str = chrono::DateTime::from_timestamp(log.timestamp as i64, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_else(|| "N/A".to_string());
        
        let cells = vec![
            Cell::from(timestamp_str),
            Cell::from(log.username.clone()),
            Cell::from(log.action.clone()),
            Cell::from(status_text).style(Style::default().fg(status_color)),
        ];
        
        Row::new(cells).height(1)
    });
    
    let audit_table = Table::new(rows, [
        Constraint::Length(20),
        Constraint::Length(15),
        Constraint::Min(20),
        Constraint::Length(12),
    ])
    .header(header)
    .block(Block::default().borders(Borders::ALL).title("Audit History (Last 50)"));
    
    f.render_widget(audit_table, chunks[1]);
}

fn render_enrichment_panel(f: &mut Frame, area: Rect, app: &App) {
    if app.enrichment_patterns.is_empty() {
        render_placeholder(f, area, "Enrichment Patterns", "No enrichment patterns configured");
        return;
    }
    
    let items: Vec<Line> = app.enrichment_patterns.iter().enumerate().map(|(i, pattern)| {
        Line::from(vec![
            Span::styled(format!("{}. ", i + 1), Style::default().fg(Color::Gray)),
            Span::styled(pattern, Style::default().fg(Color::Cyan)),
        ])
    }).collect();
    
    let list = Paragraph::new(items)
        .block(Block::default().borders(Borders::ALL).title("Enrichment Patterns (Script Interpreters)"))
        .alignment(Alignment::Left);
    
    f.render_widget(list, area);
}

fn render_zones_panel(f: &mut Frame, area: Rect, app: &App) {
    if let Some(zones) = &app.zones_config {
        if zones.red_zones.is_empty() {
            render_placeholder(f, area, "Security Zones", "No red zones configured");
            return;
        }
        
        let items: Vec<Line> = zones.red_zones.iter().enumerate().map(|(i, zone)| {
            Line::from(vec![
                Span::styled(format!("{}. ", i + 1), Style::default().fg(Color::Gray)),
                Span::styled("●", Style::default().fg(Color::Red)),
                Span::raw(" "),
                Span::styled(zone, Style::default().fg(Color::White)),
            ])
        }).collect();
        
        let list = Paragraph::new(items)
            .block(Block::default().borders(Borders::ALL).title("Red Zones (Protected Paths)").border_style(Style::default().fg(Color::Red)))
            .alignment(Alignment::Left);
        
        f.render_widget(list, area);
    } else {
        render_placeholder(f, area, "Security Zones", "Loading...");
    }
}

fn render_authorized_patterns_panel(f: &mut Frame, area: Rect, app: &App) {
    if app.authorized_patterns.is_empty() {
        render_placeholder(f, area, "Authorized Patterns", "No authorized patterns");
        return;
    }
    
    let header_cells = ["Pattern", "Mode", "Description", "Authorized On"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));
    let header = Row::new(header_cells).height(1).bottom_margin(1);
    
    let rows = app.authorized_patterns.iter().map(|pattern| {
        let pattern_str = pattern.pattern.join(" → ");
        let timestamp_str = chrono::DateTime::from_timestamp(pattern.authorized_at as i64, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
            .unwrap_or_else(|| "N/A".to_string());
        
        // Convert MatchMode enum to string
        let mode_str = format!("{:?}", pattern.match_mode);
        
        let cells = vec![
            Cell::from(pattern_str).style(Style::default().fg(Color::Green)),
            Cell::from(mode_str),
            Cell::from(pattern.description.clone()),
            Cell::from(timestamp_str),
        ];
        
        Row::new(cells).height(1)
    });
    
    let table = Table::new(rows, [
        Constraint::Percentage(35),
        Constraint::Length(10),
        Constraint::Percentage(40),
        Constraint::Length(15),
    ])
    .header(header)
    .block(Block::default().borders(Borders::ALL).title("Authorized Patterns (Allowlist)"));
    
    f.render_widget(table, area);
}

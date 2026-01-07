mod app;
mod ui;
mod integration_test;

use anyhow::Result;
use app::{App, Panel, Event, EventType};
use chrono::Local;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event as CEvent, KeyCode, KeyEvent, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    Terminal,
};
use serde_json::Value;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::AsyncBufReadExt;

const TICK_RATE: Duration = Duration::from_millis(250);

#[tokio::main]
async fn main() -> Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    
    // Create app and connect to daemon
    let app = Arc::new(Mutex::new(App::new()));
    {
        let mut app_lock = app.lock().unwrap();
        app_lock.update_statistics();
        // Try to connect to daemon
        app_lock.connect_to_daemon().await;
    }
    
    // Spawn event streaming task
    let app_clone = app.clone();
    tokio::spawn(async move {
        if let Err(e) = stream_events(app_clone).await {
            eprintln!("Event streaming error: {}", e);
        }
    });
    
    // Run the TUI
    let res = run_app(&mut terminal, app).await;
    
    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    
    if let Err(err) = res {
        eprintln!("Error: {:?}", err);
    }
    
    Ok(())
}

/// Background task that streams events from the daemon
async fn stream_events(app: Arc<Mutex<App>>) -> Result<()> {
    use kprotect_client::KprotectClient;
    
    loop {
        // Get socket path from app
        let socket_path = {
            let app_lock = app.lock().unwrap();
            app_lock.socket_path.clone()
        };
        
        let client = KprotectClient::with_socket_path(&socket_path);
        
        // Try to connect and stream
        match client.stream_events().await {
            Ok(stream) => {
                // Update connection status
                {
                    let mut app_lock = app.lock().unwrap();
                    app_lock.connection_status = app::ConnectionStatus::Connected;
                }
                
                let mut reader = tokio::io::BufReader::new(stream);
                let mut line = String::new();
                
                loop {
                    line.clear();
                    match reader.read_line(&mut line).await {
                        Ok(0) => {
                            // Connection closed
                            break;
                        }
                        Ok(_) => {
                            // Parse and add event
                            if let Ok(json) = serde_json::from_str::<Value>(&line.trim()) {
                                if let Some(event) = parse_daemon_event(&json) {
                                    let mut app_lock = app.lock().unwrap();
                                    app_lock.add_event(event);
                                }
                            }
                        }
                        Err(_) => {
                            // Error reading
                            break;
                        }
                    }
                }
                
                // Connection lost
                {
                    let mut app_lock = app.lock().unwrap();
                    app_lock.connection_status = app::ConnectionStatus::Disconnected;
                }
            }
            Err(_) => {
                // Failed to connect, mark as disconnected
                {
                    let mut app_lock = app.lock().unwrap();
                    app_lock.connection_status = app::ConnectionStatus::Disconnected;
                }
            }
        }
        
        // Wait before retrying
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Parse a daemon JSON event into an Event struct
fn parse_daemon_event(json: &Value) -> Option<Event> {
    let pid = json.get("pid")?.as_u64()? as u32;
    let signature = json.get("signature")?.as_str()?.to_string();
    let status = json.get("status")?.as_str()?;
    let target = json.get("target")?.as_str()?.to_string();
    
    let event_type = match status {
        "VERIFIED" => EventType::Verified,
        "BLOCK" => EventType::Block,
        _ => return None,
    };
    
    Some(Event {
        timestamp: Local::now(),
        event_type,
        pid,
        signature,
        path: target,
    })
}


async fn run_app<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: Arc<Mutex<App>>,
) -> Result<()> {
    let mut last_tick = Instant::now();
    let mut last_refresh = Instant::now();
    const REFRESH_INTERVAL: Duration = Duration::from_secs(5);
    
    // Initial data fetch for dashboard
    {
        let mut app_lock = app.lock().unwrap();
        app_lock.fetch_dashboard_data().await;
    }
    
    loop {
        {
            let app_lock = app.lock().unwrap();
            terminal.draw(|f| ui::render(f, &*app_lock))?;
        }
        
        let timeout = TICK_RATE
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));
        
        if event::poll(timeout)? {
            if let CEvent::Key(key) = event::read()? {
                handle_key_event(app.clone(), key).await?;
            }
        }
        
        if last_tick.elapsed() >= TICK_RATE {
            last_tick = Instant::now();
        }
        
        // Periodic data refresh for current panel
        if last_refresh.elapsed() >= REFRESH_INTERVAL {
            let mut app_lock = app.lock().unwrap();
            app_lock.refresh_current_panel_data().await;
            last_refresh = Instant::now();
        }
        
        let should_quit = {
            let app_lock = app.lock().unwrap();
            app_lock.should_quit
        };
        
        if should_quit {
            return Ok(());
        }
    }
}


async fn handle_key_event(app: Arc<Mutex<App>>, key: KeyEvent) -> Result<()> {
    // Handle Alt+Number shortcuts for panel switching
    if key.modifiers.contains(KeyModifiers::ALT) {
        match key.code {
            KeyCode::Char('1') => {
                let mut app_lock = app.lock().unwrap();
                app_lock.switch_panel(Panel::Dashboard);
                drop(app_lock);
                let mut app_lock = app.lock().unwrap();
                app_lock.fetch_dashboard_data().await;
                return Ok(());
            }
            KeyCode::Char('2') => {
                let mut app_lock = app.lock().unwrap();
                app_lock.switch_panel(Panel::Events);
                return Ok(());
            }
            KeyCode::Char('3') => {
                let mut app_lock = app.lock().unwrap();
                app_lock.switch_panel(Panel::AuthorizedSignatures);
                drop(app_lock);
                let mut app_lock = app.lock().unwrap();
                app_lock.fetch_authorized_patterns().await;
                return Ok(());
            }
            KeyCode::Char('4') => {
                let mut app_lock = app.lock().unwrap();
                app_lock.switch_panel(Panel::Zones);
                drop(app_lock);
                let mut app_lock = app.lock().unwrap();
                app_lock.fetch_zones().await;
                return Ok(());
            }
            KeyCode::Char('5') => {
                let mut app_lock = app.lock().unwrap();
                app_lock.switch_panel(Panel::Enrichment);
                drop(app_lock);
                let mut app_lock = app.lock().unwrap();
                app_lock.fetch_enrichment_patterns().await;
                return Ok(());
            }
            KeyCode::Char('6') => {
                let mut app_lock = app.lock().unwrap();
                app_lock.switch_panel(Panel::Notifications);
                drop(app_lock);
                let mut app_lock = app.lock().unwrap();
                app_lock.fetch_notification_rules().await;
                return Ok(());
            }
            KeyCode::Char('7') => {
                let mut app_lock = app.lock().unwrap();
                app_lock.switch_panel(Panel::Settings);
                drop(app_lock);
                let mut app_lock = app.lock().unwrap();
                app_lock.fetch_settings_data().await;
                return Ok(());
            }
            _ => {}
        }
    }
    
    // Handle normal keys
    let mut app_lock = app.lock().unwrap();
    match key.code {
        KeyCode::Char('q') | KeyCode::Char('Q') => {
            if !app_lock.show_help {
                app_lock.should_quit = true;
            }
        }
        KeyCode::Char('?') => {
            app_lock.toggle_help();
        }
        KeyCode::Up => {
            if !app_lock.show_help {
                app_lock.select_previous();
            }
        }
        KeyCode::Down => {
            if !app_lock.show_help {
                app_lock.select_next();
            }
        }
        KeyCode::Char('c') | KeyCode::Char('C') => {
            if !app_lock.show_help && app_lock.current_panel == Panel::Events {
                app_lock.clear_events();
            }
        }
        KeyCode::Char('a') | KeyCode::Char('A') => {
            if !app_lock.show_help && app_lock.current_panel == Panel::Events {
                app_lock.authorize_selected().await;
            }
        }
        KeyCode::Char('x') | KeyCode::Char('X') => {
            if !app_lock.show_help && app_lock.current_panel == Panel::Events {
                app_lock.revoke_selected().await;
            }
        }
        KeyCode::Esc => {
            app_lock.clear_status();
        }
        _ => {}
    }
    
    Ok(())
}

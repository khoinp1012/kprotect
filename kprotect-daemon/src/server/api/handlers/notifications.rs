use anyhow::Result;
use std::sync::Arc;
use tokio::sync::Mutex;
use crate::state::AppState;
use kprotect_common::{NotificationRule, EventTypeFilter, ActionType};

pub async fn handle_notify_list(state: &Arc<Mutex<AppState>>) -> Result<String> {
    let rules = {
        let state_lock = state.lock().await;
        state_lock.notification_manager.get_rules().await
    };
    Ok(format!("OK: {}\n", serde_json::to_string(&rules)?))
}

pub async fn handle_notify_add(state: &Arc<Mutex<AppState>>, cmd: &str, caller_uid: u32) -> Result<String> {
    if caller_uid != 0 {
        return Ok("ERROR: PERMISSION: Notification modification requires root privileges\n".to_string());
    }

    let parts: Vec<&str> = cmd.split(';').collect();
    if parts.len() < 7 {
        return Ok("ERROR: INVALID_SYNTAX: Usage: ADD_NOTIFY_RULE;name;events;path;action;dest;timeout\n".to_string());
    }

    let name = parts[1].trim().to_string();
    let events_str = parts[2].trim();
    let path = if parts[3].trim().is_empty() { None } else { Some(parts[3].trim().to_string()) };
    let action_str = parts[4].trim().to_lowercase();
    let dest = parts[5].trim().to_string();
    let timeout = parts[6].trim().parse::<u32>().unwrap_or(30);

    let event_types: Vec<EventTypeFilter> = events_str.split(',')
        .map(|s| match s.trim() {
            "Verified" => EventTypeFilter::Verified,
            "SudoVerified" => EventTypeFilter::SudoVerified,
            "SudoBlocked" => EventTypeFilter::SudoBlocked,
            _ => EventTypeFilter::Blocked,
        })
        .collect();

    let action_type = match action_str.as_str() {
        "script" => ActionType::Script,
        _ => ActionType::Webhook,
    };

    let rule = NotificationRule {
        id: 0, // Will be set by manager
        name,
        event_types,
        path_pattern: path,
        action_type,
        destination: dest,
        enabled: true,
        timeout,
        created_at: 0, // Will be set by manager
        last_triggered: None,
        trigger_count: 0,
        success_count: 0,
        failure_count: 0,
        timeout_count: 0,
        total_execution_ms: 0,
    };

    let manager = {
        let state_lock = state.lock().await;
        state_lock.notification_manager.clone()
    };

    match manager.add_rule(rule).await {
        Ok(id) => Ok(format!("OK: Rule added with ID: {}\n", id)),
        Err(e) => Ok(format!("ERROR: FAILED_TO_ADD_RULE: {}\n", e)),
    }
}

pub async fn handle_notify_remove(state: &Arc<Mutex<AppState>>, cmd: &str, caller_uid: u32) -> Result<String> {
    if caller_uid != 0 {
        return Ok("ERROR: PERMISSION: Notification modification requires root privileges\n".to_string());
    }

    let parts: Vec<&str> = cmd.split(';').collect();
    if parts.len() < 2 {
        return Ok("ERROR: INVALID_SYNTAX: Usage: REMOVE_NOTIFY_RULE;id\n".to_string());
    }

    let id = parts[1].trim().parse::<u32>().map_err(|_| anyhow::anyhow!("Invalid rule ID"))?;

    let manager = {
        let state_lock = state.lock().await;
        state_lock.notification_manager.clone()
    };

    match manager.remove_rule(id).await {
        Ok(_) => Ok(format!("OK: Rule {} removed\n", id)),
        Err(e) => Ok(format!("ERROR: FAILED_TO_REMOVE_RULE: {}\n", e)),
    }
}

pub async fn handle_notify_toggle(state: &Arc<Mutex<AppState>>, cmd: &str, caller_uid: u32) -> Result<String> {
    if caller_uid != 0 {
        return Ok("ERROR: PERMISSION: Notification modification requires root privileges\n".to_string());
    }

    let parts: Vec<&str> = cmd.split(';').collect();
    if parts.len() < 3 {
        return Ok("ERROR: INVALID_SYNTAX: Usage: TOGGLE_NOTIFY_RULE;id;enabled\n".to_string());
    }

    let id = parts[1].trim().parse::<u32>().map_err(|_| anyhow::anyhow!("Invalid rule ID"))?;
    let enabled = parts[2].trim().parse::<bool>().map_err(|_| anyhow::anyhow!("Invalid enabled value (true/false)"))?;

    let manager = {
        let state_lock = state.lock().await;
        state_lock.notification_manager.clone()
    };

    match manager.toggle_rule(id, enabled).await {
        Ok(_) => Ok(format!("OK: Rule {} is now {}\n", id, if enabled { "enabled" } else { "disabled" })),
        Err(e) => Ok(format!("ERROR: FAILED_TO_TOGGLE_RULE: {}\n", e)),
    }
}

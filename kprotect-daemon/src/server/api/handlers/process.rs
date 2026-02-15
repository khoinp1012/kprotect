use anyhow::Result;
use std::sync::Arc;
use tokio::sync::Mutex;
use serde_json::json;
use crate::state::AppState;

pub async fn handle_inspect(state: &Arc<Mutex<AppState>>, signature: u64) -> Result<Option<String>> {
    let lineage_cache = {
        let state_lock = state.lock().await;
        state_lock.lineage_cache.clone()
    };
    
    let find_result = lineage_cache.iter()
        .find(|r| r.value().signature == signature)
        .map(|r| {
            let node = r.value();
            let info = json!({
                "signature": format!("0x{:x}", signature),
                "lineage": {
                    "path": node.path,
                    "arg": node.arg,
                    "ppid": node.ppid,
                    "start_time": node.start_time
                }
            });
            format!("OK: {}\n", info)
        });
        
    Ok(find_result)
}

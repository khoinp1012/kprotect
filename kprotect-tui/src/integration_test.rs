
#[cfg(test)]
mod tests {
    use crate::app::{App, EventType};
    use tokio::time::Duration;

    #[tokio::test]
    async fn test_app_integration() {
        println!("TEST: Initializing App...");
        let mut app = App::new();
        
        // 1. Test Connection
        println!("TEST: Connecting to daemon...");
        app.connect_to_daemon().await;
        
        // Wait a bit for connection
        tokio::time::sleep(Duration::from_millis(500)).await;
        
        assert_eq!(app.connection_status.as_str(), "Connected", "Failed to connect to daemon");
        println!("TEST: Connected successfully!");

        // 2. Select a BLOCK event from demo events
        // Find index of a BLOCK event
        let block_idx = app.events.iter().position(|e| e.event_type == EventType::Block).expect("No BLOCK events in demo data");
        app.selected_index = block_idx;
        
        let event = app.get_selected_event().unwrap();
        println!("TEST: Selected BLOCK event: {} ({})", event.signature, event.path);
        let sig_hex = event.signature.clone();

        // 3. Authorize
        println!("TEST: Attempting authorization...");
        app.authorize_selected().await;
        
        // Check status message
        if let Some(msg) = &app.status_message {
            println!("TEST: Status message: {}", msg.text);
            assert!(!msg.is_error, "Authorization returned error: {}", msg.text);
            assert!(msg.text.contains("Authorized"), "Message did not confirm authorization");
        } else {
            panic!("TEST: No status message after authorization attempt");
        }

        // 4. Revoke
        println!("TEST: Attempting revocation...");
        app.revoke_selected().await;
         
        // Check status message
        if let Some(msg) = &app.status_message {
             println!("TEST: Status message: {}", msg.text);
             assert!(!msg.is_error, "Revocation returned error: {}", msg.text);
             assert!(msg.text.contains("Revoked"), "Message did not confirm revocation");
        } else {
             panic!("TEST: No status message after revocation attempt");
        }
        
        println!("TEST: Integration test passed!");
    }
}

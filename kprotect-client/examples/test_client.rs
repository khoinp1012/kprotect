use kprotect_client::KprotectClient;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client = KprotectClient::new();
    
    println!("=== Testing kprotect-client ===\n");
    
    // Test 1: PING
    println!("1. Testing ping...");
    match client.ping().await {
        Ok(response) => println!("   ✅ PING: {}", response),
        Err(e) => println!("   ❌ PING failed: {}", e),
    }
    
    // Test 2: VERSION
    println!("\n2. Testing version...");
    match client.version().await {
        Ok(response) => println!("   ✅ VERSION: {}", response),
        Err(e) => println!("   ❌ VERSION failed: {}", e),
    }
    
    // Test 3: CAPABILITIES
    println!("\n3. Testing capabilities...");
    match client.capabilities().await {
        Ok(caps) => {
            println!("   ✅ CAPABILITIES:");
            println!("      Version: {}", caps.version);
            println!("      Protocol: {}", caps.protocol_version);
            println!("      Features: {:?}", caps.features);
            println!("      Current user: {}", caps.permissions.current_user);
            println!("      Can authorize: {}", caps.permissions.can_authorize);
        },
        Err(e) => println!("   ❌ CAPABILITIES failed: {}", e),
    }
    
    // Test 4: SCHEMA
    println!("\n4. Testing schema...");
    match client.schema("authorized_signatures").await {
        Ok(schema) => {
            println!("   ✅ SCHEMA for {}:", schema.resource);
            println!("      Description: {}", schema.description);
            println!("      Fields: {}", schema.fields.len());
            for field in &schema.fields {
                println!("        - {}: {} ({})", field.name, field.field_type, field.description);
            }
            println!("      Actions: {}", schema.actions.len());
            for action in &schema.actions {
                println!("        - {}: {} (root: {})", action.name, action.command, action.requires_root);
            }
        },
        Err(e) => println!("   ❌ SCHEMA failed: {}", e),
    }
    
    println!("\n=== All tests complete ===");
    
    Ok(())
}

export interface Event {
    id: number | string;
    timestamp: string;
    last_seen?: number | string; // For grouping validation
    status: 'Verified' | 'Blocked' | 'Birth' | 'Exit' | 'Unknown';
    pid: number;
    // signature is deprecated but might be present in old logs or transition
    // hash is also deprecated
    chain: string[];   // Full process lineage
    path: string;      // The target process path (usually last in chain)
    complete?: boolean; // Is the lineage complete / started from root?
    signature?: number;
    count?: number; // Grouping counter
}

export interface Stats {
    total: number;
    verified: number;
    blocked: number;
    birth: number;
}

export interface AuthorizedPattern {
    pattern: string[];
    match_mode: 'Exact' | 'Suffix';
    description: string;
    authorized_at: number;
}

export interface ZonesConfig {
    red_zones: string[];
    green_zones: string[];
}
export type Capabilities = Record<string, any>;

export interface LogConfig {
    event_log_retention_days: number;
    audit_log_retention_days: number;
    event_log_enabled: boolean;
    audit_log_enabled: boolean;
}

export interface AuditLog {
    timestamp: number;
    action: string;
    username: string;
    details: any;
    success: boolean;
}

export interface NotificationRule {
    id: number;
    name: string;
    enabled: boolean;
    event_types: ('Verified' | 'Blocked')[];
    path_pattern: string | null;
    action_type: 'Script' | 'Webhook';
    destination: string;
    timeout: number;
    created_at: number;
    last_triggered: number | null;
    trigger_count: number;
    // Statistics
    success_count: number;
    failure_count: number;
    timeout_count: number;
    total_execution_ms: number;
}

export interface NotificationStats {
    rule_id: number;
    rule_name: string;
    total_triggers: number;
    success_count: number;
    failure_count: number;
    timeout_count: number;
    success_rate: number;
    avg_execution_ms: number;
    last_triggered: number | null;
}

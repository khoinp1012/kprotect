import { invoke } from '@tauri-apps/api/core';
import { AuthorizedPattern, ZonesConfig, Capabilities, Event, LogConfig, AuditLog } from '../types';

export const api = {
    // Patterns / Allowlist
    getAllowlist: () => invoke<AuthorizedPattern[]>('get_patterns'),
    authorizePattern: (pattern: string[], mode: 'Exact' | 'Suffix', description: string) =>
        invoke('authorize_pattern', { pattern, mode, description }),
    revokePattern: (pattern: string[], matchMode: 'Exact' | 'Suffix') =>
        invoke('revoke_pattern', { pattern, matchMode }),

    // Root Worker
    startRootSession: () => invoke<string>('start_root_session'),
    stopRoot: () => invoke('stop_root_worker'),
    checkRootStatus: () => invoke<boolean>('check_root_worker_status'),

    // Zones
    getZones: () => invoke<ZonesConfig>('get_zones'),
    addZone: (zone_type: string, pattern: string) => invoke('add_zone', { zoneType: zone_type, pattern }),
    removeZone: (zone_type: string, pattern: string) => invoke('remove_zone', { zoneType: zone_type, pattern }),

    // Enrichment (Policies)
    getEnrichmentPatterns: () => invoke<{ enrichment_patterns: string[] }>('get_enrichment_patterns'),
    addEnrichmentPattern: (pattern: string) => invoke('add_enrichment_pattern', { pattern }),
    removeEnrichmentPattern: (pattern: string) => invoke('remove_enrichment_pattern', { pattern }),

    // System
    getCapabilities: () => invoke<Capabilities>('get_capabilities'),

    // Monitoring
    getDaemonStatus: () => invoke<DaemonStatus>('get_daemon_status'),
    getEncryptionInfo: () => invoke<EncryptionInfo>('get_encryption_info'),
    getSystemInfo: () => invoke<SystemInfo>('get_system_info'),

    // Log Management
    getLogConfig: () => invoke<LogConfig>('get_log_config'),
    setLogRetention: (events: number, audit: number) => invoke('set_log_retention', { events, audit }),
    getSecurityEvents: (count: number, offset: number = 0) => invoke<Event[]>('get_security_events', { count, offset }),
    getAuditLogs: (count: number, offset: number = 0) => invoke<AuditLog[]>('get_audit_logs', { count, offset }),

    // Notifications
    getNotificationRules: () => invoke('get_notification_rules'),
    addNotificationRule: (rule: any) => invoke('add_notification_rule', rule),
    removeNotificationRule: (id: number) => invoke('remove_notification_rule', { id }),
    toggleNotificationRule: (id: number, enabled: boolean) => invoke('toggle_notification_rule', { id, enabled }),

    // Resource Usage
    getResourceUsage: () => invoke<SystemStats>('get_resource_usage'),
};

export interface ResourceUsage {
    current: number;
    max: number;
}

export interface ZoneStats {
    prefix: ResourceUsage;
    suffix: ResourceUsage;
    exact: ResourceUsage;
}

export interface SystemStats {
    authorized_chains: ResourceUsage;
    enrichment: ResourceUsage;
    zones: ZoneStats;
}




// Type definitions for monitoring responses
export interface DaemonStatus {
    uptime_seconds: number;
    ebpf_loaded: boolean;
    active_connections: number;
    socket_path: string;
}

export interface PolicyFileInfo {
    path: string;
    last_modified: number;
}

export interface EncryptionInfo {
    enabled: boolean;
    algorithm: string;
    key_fingerprint: string;
    policy_files: PolicyFileInfo[];
}

export interface SystemInfo {
    authorized_patterns: number;
    red_zones: number;
    enrichment_patterns: number;
    events_verified: number;
    events_blocked: number;
    lineage_cache_size: number;
    event_log_size_bytes: number;
    audit_log_size_bytes: number;
    ebpf_maps: Record<string, { size: number; capacity: number }>;
}

import { render, screen } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { Dashboard } from './Dashboard';
import { api } from '../api';

// Mock api
vi.mock('../api', () => ({
    api: {
        getDaemonStatus: vi.fn(),
        getEncryptionInfo: vi.fn(),
        getSystemInfo: vi.fn(),
    },
}));

describe('Dashboard Page', () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    it('displays "eBPF Engine Active" when daemon is running', async () => {
        (api.getDaemonStatus as any).mockResolvedValue({
            ebpf_loaded: true,
            uptime_seconds: 3600,
            active_connections: 2,
            socket_path: '/tmp/kprotect.sock',
        });
        (api.getEncryptionInfo as any).mockResolvedValue({
            enabled: true,
            algorithm: 'AES-256-GCM',
            key_fingerprint: '1234567890abcdef',
            policy_files: [],
        });
        (api.getSystemInfo as any).mockResolvedValue({
            events_verified: 100,
            events_blocked: 10,
            authorized_patterns: 5,
            red_zones: 2,
            enrichment_patterns: 1,
            lineage_cache_size: 50,
            event_log_size_bytes: 1024,
            audit_log_size_bytes: 512,
            ebpf_maps: {},
        });

        render(<Dashboard />);

        expect(await screen.findByText(/eBPF Engine Active/i)).toBeInTheDocument();
        expect(screen.getByText(/AES-256 Protected/i)).toBeInTheDocument();
    });

    it('displays "eBPF Engine Offline" when ebpf_loaded is false', async () => {
        (api.getDaemonStatus as any).mockResolvedValue({
            ebpf_loaded: false,
            uptime_seconds: 0,
            active_connections: 0,
            socket_path: '/tmp/kprotect.sock',
        });
        (api.getEncryptionInfo as any).mockResolvedValue({
            enabled: false,
            algorithm: 'None',
            key_fingerprint: '',
            policy_files: [],
        });
        (api.getSystemInfo as any).mockResolvedValue({
            events_verified: 0,
            events_blocked: 0,
            authorized_patterns: 0,
            red_zones: 0,
            enrichment_patterns: 0,
            lineage_cache_size: 0,
            event_log_size_bytes: 0,
            audit_log_size_bytes: 0,
            ebpf_maps: {},
        });

        render(<Dashboard />);

        expect(await screen.findByText(/eBPF Engine Offline/i)).toBeInTheDocument();
    });
});

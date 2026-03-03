import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { Dashboard } from './Dashboard';
import { api } from '../api';

// Mock api
vi.mock('../api', () => ({
    api: {
        getDaemonStatus: vi.fn(),
        getEncryptionInfo: vi.fn(),
        getSystemInfo: vi.fn(),
        setEngineEnabled: vi.fn(),
        setFileProtection: vi.fn(),
        setSudoBypass: vi.fn(),
    },
}));

const mockGlobal = {
    events: [] as any[],
    elevationEvents: [] as any[],
    isRootActive: true,
};

// Mock GlobalContext
vi.mock('../context/GlobalContext', () => ({
    useGlobal: () => mockGlobal,
}));

describe('Dashboard Page', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mockGlobal.isRootActive = true;
        mockGlobal.events = [];
        mockGlobal.elevationEvents = [];

        // Default mock resolutions
        (api.getDaemonStatus as any).mockResolvedValue({
            ebpf_loaded: true, uptime_seconds: 3600, active_connections: 2, socket_path: '/tmp/kprotect.sock'
        });
        (api.getSystemInfo as any).mockResolvedValue({
            events_verified: 0, events_blocked: 0, authorized_patterns: 0, red_zones: 0, enrichment_patterns: 0,
            lineage_cache_size: 0, event_log_size_bytes: 0, audit_log_size_bytes: 0, ebpf_maps: {},
            engine_enabled: true, file_protection_enabled: true, sudo_bypass_enabled: true,
        });
    });

    it('displays the 3-pillar layout: Daemon Engine, File Protection, and Quick Sudo', async () => {
        render(<Dashboard />);

        expect(await screen.findByText(/Daemon Engine/i)).toBeInTheDocument();
        expect(screen.getByText(/File Protection/i)).toBeInTheDocument();
        expect(screen.getByText(/Quick Sudo/i)).toBeInTheDocument();

        expect(screen.getByText(/Engine is Running/i)).toBeInTheDocument();
        expect(screen.getByText(/Enforcement Active/i)).toBeInTheDocument();
        expect(screen.getByText(/Bypass Engine Active/i)).toBeInTheDocument();
    });

    it('disables toggles when isRootActive is false', async () => {
        mockGlobal.isRootActive = false;

        render(<Dashboard />);

        const engineSwitch = await screen.findByLabelText(/Toggle Engine/i);
        expect(engineSwitch).toBeDisabled();

        fireEvent.click(engineSwitch);
        expect(api.setEngineEnabled).not.toHaveBeenCalled();
    });

    it('displays recent activity events in pillars', async () => {
        mockGlobal.events = [
            { id: 1, path: '/etc/passwd', status: 'Blocked', event_type: 1, timestamp: '2026-02-16T12:00:00Z', pid: 1234, chain: [] },
            { id: 2, path: '/bin/ls', status: 'Verified', event_type: 1, timestamp: '2026-02-16T12:01:00Z', pid: 5678, chain: [] },
        ];
        mockGlobal.elevationEvents = [
            { id: 3, path: '/usr/bin/sudo', status: 'Elevation', event_type: 5, pid: 9999, timestamp: '2026-02-16T12:02:00Z', chain: [] },
        ];

        render(<Dashboard />);

        // Wait for re-render after API calls
        await waitFor(() => {
            expect(screen.getByText(/passwd/i)).toBeInTheDocument();
        });

        expect(screen.getByText(/ls/i)).toBeInTheDocument();

        // Use a more specific query for sudo to avoid matching "Quick Sudo" title
        const sudoElements = screen.getAllByText(/sudo/i);
        // At least one should be in the activity row (the other is the card title)
        expect(sudoElements.length).toBeGreaterThanOrEqual(2);

        expect(screen.getByText(/PID 9999/i)).toBeInTheDocument();
    });

    it('displays empty state messaging when no events', async () => {
        render(<Dashboard />);

        expect(await screen.findByText(/No recent file events/i)).toBeInTheDocument();
        expect(screen.getByText(/No recent elevations/i)).toBeInTheDocument();
    });

    it('displays "Engine is Paused" when engine_enabled is false', async () => {
        (api.getSystemInfo as any).mockResolvedValue({
            events_verified: 0, events_blocked: 0, authorized_patterns: 0, red_zones: 0, enrichment_patterns: 0,
            lineage_cache_size: 0, event_log_size_bytes: 0, audit_log_size_bytes: 0, ebpf_maps: {},
            engine_enabled: false, file_protection_enabled: false, sudo_bypass_enabled: false,
        });

        render(<Dashboard />);

        expect(await screen.findByText(/Engine is Paused/i)).toBeInTheDocument();
        expect(screen.getByText(/Protection Disabled/i)).toBeInTheDocument();
        expect(screen.getByText(/Bypass Disabled/i)).toBeInTheDocument();
    });
});

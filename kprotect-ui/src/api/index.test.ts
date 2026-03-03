import { describe, it, expect, vi, beforeEach } from 'vitest';
import { api } from './index';
import { invoke } from '@tauri-apps/api/core';

// Mock Tauri invoke
vi.mock('@tauri-apps/api/core', () => ({
    invoke: vi.fn(),
}));

describe('Frontend API', () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    it('setEngineEnabled calls the correct Tauri command', async () => {
        (invoke as any).mockResolvedValue('OK');
        await api.setEngineEnabled(true);
        expect(invoke).toHaveBeenCalledWith('set_engine_enabled', { enabled: true });

        await api.setEngineEnabled(false);
        expect(invoke).toHaveBeenCalledWith('set_engine_enabled', { enabled: false });
    });

    it('setFileProtection calls the correct Tauri command', async () => {
        (invoke as any).mockResolvedValue('OK');
        await api.setFileProtection(true);
        expect(invoke).toHaveBeenCalledWith('set_file_protection', { enabled: true });
    });

    it('setSudoBypass calls the correct Tauri command', async () => {
        (invoke as any).mockResolvedValue('OK');
        await api.setSudoBypass(true);
        expect(invoke).toHaveBeenCalledWith('set_sudo_bypass', { enabled: true });
    });

    it('getSystemInfo returns correct structured data', async () => {
        const mockData = {
            engine_enabled: true,
            file_protection_enabled: true,
            sudo_bypass_enabled: true,
            events_verified: 100,
            events_blocked: 10,
        };
        (invoke as any).mockResolvedValue(mockData);

        const result = await api.getSystemInfo();
        expect(invoke).toHaveBeenCalledWith('get_system_info');
        expect(result).toEqual(mockData);
    });

    it('addZone calls the correct Tauri command', async () => {
        (invoke as any).mockResolvedValue('OK');
        await api.addZone('red', '/etc/passwd');
        expect(invoke).toHaveBeenCalledWith('add_zone', { zoneType: 'red', pattern: '/etc/passwd' });
    });

    it('addSudoRule calls the correct Tauri command', async () => {
        (invoke as any).mockResolvedValue('OK');
        await api.addSudoRule(['/bin/bash', 'apt update'], 'Update packages');
        expect(invoke).toHaveBeenCalledWith('add_sudo_rule', {
            pattern: ['/bin/bash', 'apt update'],
            description: 'Update packages'
        });
    });
});

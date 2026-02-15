import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { Notifications } from './Notifications';
import { api } from '../api';
import { useGlobal } from '../context/GlobalContext';

// Mock dependencies
vi.mock('../api', () => ({
    api: {
        getNotificationRules: vi.fn(),
        addNotificationRule: vi.fn(),
        removeNotificationRule: vi.fn(),
        toggleNotificationRule: vi.fn(),
    },
}));

vi.mock('../context/GlobalContext', () => ({
    useGlobal: vi.fn(),
}));

vi.mock('sonner', () => ({
    toast: {
        error: vi.fn(),
        success: vi.fn(),
    },
}));

vi.mock('@tauri-apps/api/path', () => ({
    homeDir: vi.fn(() => Promise.resolve('/home/user')),
}));

const mockContextValue = {
    isRootActive: true,
    blockedAlertsEnabled: true,
    setBlockedAlertsEnabled: vi.fn(),
    authorizedAlertsEnabled: false,
    setAuthorizedAlertsEnabled: vi.fn(),
};

describe('Notifications Page', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        (useGlobal as any).mockReturnValue(mockContextValue);
    });

    it('loads and displays notification rules', async () => {
        const mockRules = [
            {
                id: 1,
                name: 'Test Rule',
                event_types: ['Blocked'],
                path_pattern: '/bin/bash',
                action_type: 'Script',
                destination: '/path/to/script',
                enabled: true,
                timeout: 30,
                trigger_count: 5,
                success_count: 5,
                failure_count: 0,
                timeout_count: 0,
                total_execution_ms: 100,
                last_triggered: Date.now() / 1000 - 3600,
            },
        ];

        (api.getNotificationRules as any).mockResolvedValue(mockRules);

        render(<Notifications />);

        expect(await screen.findByText(/Test Rule/i)).toBeInTheDocument();
        expect(screen.getByText('/bin/bash')).toBeInTheDocument();
    });

    it('opens "Add Rule" modal when clicking New Rule button', async () => {
        (api.getNotificationRules as any).mockResolvedValue([]);

        render(<Notifications />);

        const addButton = screen.getByText(/New Rule/i);
        fireEvent.click(addButton);

        expect(screen.getByPlaceholderText(/e.g. Alert Admin on Blocked Access/i)).toBeInTheDocument();
    });
});

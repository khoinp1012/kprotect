import { describe, it, expect } from 'vitest';
import { mapRawEventToUI, compressEvents } from './GlobalContext';
import { Event } from '../types';

describe('GlobalContext Utilities', () => {
    describe('mapRawEventToUI', () => {
        it('transforms raw backend event to UI Event correctly', () => {
            const raw = {
                id: 1,
                timestamp: 1672531200, // 2023-01-01
                status: 'Verified',
                pid: 1234,
                comm: 'bash',
                target: '/etc/passwd',
                chain: ['systemd', 'sshd', 'bash']
            };
            const result = mapRawEventToUI(raw);
            expect(result.id).toBe(1);
            expect(result.status).toBe('Verified');
            expect(result.pid).toBe(1234);
            expect(result.path).toBe('/etc/passwd');
            expect(result.chain).toEqual(['systemd', 'sshd', 'bash']);
        });

        it('handles missing fields with defaults', () => {
            const raw = { status: 'Blocked' };
            const result = mapRawEventToUI(raw);
            expect(result.status).toBe('Blocked');
            expect(result.pid).toBe(0);
            expect(result.chain).toEqual([]);
        });
    });

    describe('compressEvents', () => {
        it('deduplicates identical events and aggregates counts', () => {
            const e1: Event = {
                id: 1,
                timestamp: '2023-01-01T00:00:00Z',
                status: 'Blocked',
                pid: 100,
                path: '/etc/shadow',
                chain: ['bash'],
                complete: true
            };
            const e2: Event = { ...e1, id: 2, timestamp: '2023-01-01T00:00:01Z', pid: 101 };
            const e3: Event = { ...e1, id: 3, path: '/other' };

            const compressed = compressEvents([e1, e2, e3]);

            // e1 and e2 should be merged (same status, path, chain)
            // e3 should be separate
            expect(compressed.length).toBe(2);

            const merged = compressed.find(e => e.path === '/etc/shadow')!;
            expect(merged.count).toBe(2);
            // Should have latest timestamp
            expect(merged.timestamp).toBe('2023-01-01T00:00:01Z');
            expect(merged.pid).toBe(101);

            const separate = compressed.find(e => e.path === '/other')!;
            expect(separate.count).toBe(1);
        });

        it('returns empty array for empty input', () => {
            expect(compressEvents([])).toEqual([]);
        });
    });
});

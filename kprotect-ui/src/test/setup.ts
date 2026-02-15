import '@testing-library/jest-dom';
import { vi } from 'vitest';

// Mock Tauri/API globals if needed
vi.mock('@tauri-apps/api/core', () => ({
    invoke: vi.fn(),
}));

// Add any other global mocks here

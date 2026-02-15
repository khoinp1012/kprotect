import { render, screen } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import { StatusBadge } from './EventList';

describe('StatusBadge', () => {
    it('renders "Authorized" when originalStatus is "Verified"', () => {
        render(<StatusBadge originalStatus="Verified" />);
        expect(screen.getByText('Authorized')).toBeInTheDocument();
        expect(screen.queryByText('Blocked')).not.toBeInTheDocument();
    });

    it('renders "Blocked" when originalStatus is "Blocked" and not now authorized', () => {
        render(<StatusBadge originalStatus="Blocked" isNowAuthorized={false} />);
        expect(screen.getByText('Blocked')).toBeInTheDocument();
        expect(screen.queryByText('Now Authorized')).not.toBeInTheDocument();
    });

    it('renders "Blocked" and "Now Authorized" when originalStatus is "Blocked" and isNowAuthorized is true', () => {
        render(<StatusBadge originalStatus="Blocked" isNowAuthorized={true} />);
        expect(screen.getByText('Blocked')).toBeInTheDocument();
        expect(screen.getByText('Now Authorized')).toBeInTheDocument();
    });

    it('renders "Unknown" for unknown status', () => {
        render(<StatusBadge originalStatus="Unknown" />);
        expect(screen.getByText('Unknown')).toBeInTheDocument();
    });

    it('renders "Birth" for birth status', () => {
        render(<StatusBadge originalStatus="Birth" />);
        expect(screen.getByText('Birth')).toBeInTheDocument();
    });
});

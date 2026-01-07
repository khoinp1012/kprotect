/**
 * kprotect-ui: Modern Security Management Interface
 * Copyright (C) 2026 khoinp1012
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import { useState } from 'react';
import { GlobalProvider } from './context/GlobalContext';
import { Layout } from './components/Layout';
import { EventList } from './components/EventList';
import { AuthorizedPatterns } from './components/AuthorizedPatterns';
import { Policies } from './pages/Policies';
import { Settings } from './pages/Settings';
import { Dashboard } from './pages/Dashboard';
import { Notifications } from './pages/Notifications';
import { Toaster } from 'sonner';

function AppContent() {
    const [activeTab, setActiveTab] = useState<'dashboard' | 'events' | 'allowlist' | 'zones' | 'enrichment' | 'notifications' | 'settings'>('dashboard');

    const renderContent = () => {
        switch (activeTab) {
            case 'dashboard':
                return <Dashboard />;
            case 'events':
                return <EventList />;
            case 'allowlist':
                return <AuthorizedPatterns />;
            case 'zones':
                return <Policies initialTab="zones" />;
            case 'enrichment':
                return <Policies initialTab="enrichment" />;
            case 'notifications':
                return <Notifications />;
            case 'settings':
                return <Settings />;
            default:
                return null;
        }
    };

    const titles: Record<string, string> = {
        dashboard: 'Security Dashboard',
        events: 'Live Event Feed',
        allowlist: 'Authorized Patterns',
        zones: 'Security Zones',
        enrichment: 'Interpreter Tracing',
        notifications: 'Event Notifications',
        settings: 'System Settings'
    };

    return (
        <Layout activeTab={activeTab} setActiveTab={setActiveTab} title={titles[activeTab]}>
            <Toaster position="bottom-right" richColors />
            {renderContent()}
        </Layout>
    );
}

function App() {
    return (
        <GlobalProvider>
            <AppContent />
        </GlobalProvider>
    );
}

export default App;

import { useState } from 'react';
import { List, CheckCircle, Code2, Layers } from 'lucide-react';
import { Policies } from './Policies';
import { EventList } from '../components/EventList';
import { AuthorizedPatterns } from '../components/AuthorizedPatterns';

interface FileProtectionProps {
    initialTab?: 'zones' | 'allowlist' | 'events' | 'enrichment';
}

export function FileProtection({ initialTab = 'events' }: FileProtectionProps = {}) {
    const [activeTab, setActiveTab] = useState<'zones' | 'allowlist' | 'events' | 'enrichment'>(initialTab);

    const renderTabContent = () => {
        switch (activeTab) {
            case 'zones':
                return <Policies initialTab="zones" />;
            case 'allowlist':
                return <AuthorizedPatterns />;
            case 'events':
                return <EventList />;
            case 'enrichment':
                return <Policies initialTab="enrichment" />;
            default:
                return null;
        }
    };

    const tabs = [
        { id: 'events', label: 'Security Live Feed', icon: <List size={16} /> },
        { id: 'zones', label: 'Security Zones', icon: <Layers size={16} /> },
        { id: 'allowlist', label: 'Lineage Allow List', icon: <CheckCircle size={16} /> },
        { id: 'enrichment', label: 'Interpreters', icon: <Code2 size={16} /> },
    ];

    return (
        <div className="space-y-6">
            <div className="flex items-center space-x-2 border-b border-zinc-200">
                {tabs.map(tab => (
                    <button
                        key={tab.id}
                        onClick={() => setActiveTab(tab.id as any)}
                        className={`flex items-center space-x-2 px-4 py-3 text-sm font-bold transition-all border-b-2 ${activeTab === tab.id
                            ? 'border-indigo-600 text-indigo-600'
                            : 'border-transparent text-zinc-500 hover:text-zinc-700 hover:bg-zinc-50'
                            }`}
                    >
                        {tab.icon}
                        <span>{tab.label}</span>
                    </button>
                ))}
            </div>
            <div className="animate-in fade-in slide-in-from-bottom-4 duration-300">
                {renderTabContent()}
            </div>
        </div>
    );
}

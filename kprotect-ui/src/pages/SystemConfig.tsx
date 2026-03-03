import { useState } from 'react';
import { Bell, Settings2 } from 'lucide-react';
import { Settings } from './Settings';
import { Notifications } from './Notifications';

interface SystemConfigProps {
    initialTab?: 'notifications' | 'daemon';
}

export function SystemConfig({ initialTab = 'notifications' }: SystemConfigProps = {}) {
    const [activeTab, setActiveTab] = useState<'notifications' | 'daemon'>(initialTab);

    const renderTabContent = () => {
        switch (activeTab) {
            case 'notifications':
                return <Notifications />;
            case 'daemon':
                return <Settings />;
            default:
                return null;
        }
    };

    const tabs = [
        { id: 'notifications', label: 'Notification Engine', icon: <Bell size={16} /> },
        { id: 'daemon', label: 'Daemon Settings', icon: <Settings2 size={16} /> },
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

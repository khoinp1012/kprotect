import { useState } from 'react';
import { Bell, Settings2, Shield, Lock } from 'lucide-react';
import { Settings } from './Settings';
import { Notifications } from './Notifications';

interface SystemConfigProps {
    initialTab?: 'notifications' | 'daemon' | 'encryption';
}

export function SystemConfig({ initialTab = 'notifications' }: SystemConfigProps = {}) {
    const [activeTab, setActiveTab] = useState<'notifications' | 'daemon' | 'encryption'>(initialTab);

    const renderTabContent = () => {
        switch (activeTab) {
            case 'notifications':
                return <Notifications />;
            case 'daemon':
                return <Settings />;
            case 'encryption':
                return (
                    <div className="p-12 text-center bg-white border border-zinc-200 rounded-xl shadow-sm">
                        <Lock className="mx-auto text-zinc-200 mb-4" size={32} />
                        <h3 className="text-zinc-900 font-bold">Key Management</h3>
                        <p className="text-zinc-500 text-sm mt-2">Policy encryption keys are managed at the daemon level.</p>
                        <button className="mt-6 px-4 py-2 bg-indigo-600 text-white rounded-xl text-xs font-bold hover:bg-indigo-700 transition-all shadow-lg shadow-indigo-100">
                            Rotate Security Key
                        </button>
                    </div>
                );
            default:
                return null;
        }
    };

    const tabs = [
        { id: 'notifications', label: 'Notification Engine', icon: <Bell size={16} /> },
        { id: 'daemon', label: 'Daemon Settings', icon: <Settings2 size={16} /> },
        { id: 'encryption', label: 'Security & Keys', icon: <Shield size={16} /> },
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

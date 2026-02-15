import { ReactNode, useState } from 'react';
import {
    Menu, Zap, CheckCircle, Power,
    LayoutDashboard, Shield, Fingerprint, Settings2
} from "lucide-react";
import { useGlobal } from '../context/GlobalContext';
import { api } from '../api';
import { toast } from 'sonner';

interface LayoutProps {
    children: ReactNode;
    activeTab: 'dashboard' | 'file-protection' | 'quick-sudo' | 'system-config';
    setActiveTab: (tab: any) => void;
    title: string;
}

export function Layout({ children, activeTab, setActiveTab, title }: LayoutProps) {
    const { isRootActive, checkRootStatus, refreshAllowlist } = useGlobal();
    const [isSidebarOpen, setIsSidebarOpen] = useState(false);

    const handleTriggerRoot = async () => {
        try {
            const promise = api.startRootSession();
            toast.promise(promise, {
                loading: 'Authenticating...',
                success: 'Root Session Started',
                error: (err) => `Failed: ${err}`
            });
            await promise;

            let attempts = 0;
            while (attempts < 300) {
                await new Promise(r => setTimeout(r, 200));
                const active = await api.checkRootStatus();
                if (active) {
                    await checkRootStatus();
                    await refreshAllowlist();
                    return;
                }
                attempts++;
            }
        } catch (e: any) { }
    };

    const handleStopRoot = async () => {
        try {
            await api.stopRoot();
            toast.info("Root Session Stopped");
        } catch (e) {
            console.error("Stop root failed:", e);
        } finally {
            await checkRootStatus();
        }
    };

    const sidebarItems = [
        { id: 'dashboard', label: 'Dashboard', icon: <LayoutDashboard size={20} />, hub: 'Global Status' },
        { id: 'file-protection', label: 'File Protection', icon: <Shield size={20} />, hub: 'Security' },
        { id: 'quick-sudo', label: 'Quick Sudo', icon: <Fingerprint size={20} />, hub: 'Security' },
        { id: 'system-config', label: 'System Config', icon: <Settings2 size={20} />, hub: 'Management' },
    ];

    const hubGroups = ['Global Status', 'Security', 'Management'];

    return (
        <div className="flex h-screen bg-[#FDFDFE] overflow-hidden text-zinc-900 font-sans selection:bg-indigo-100 selection:text-indigo-900">
            {/* Sidebar */}
            <aside className={`fixed inset-y-0 left-0 z-50 w-72 bg-white border-r border-zinc-200 transform transition-all duration-300 ease-in-out lg:relative lg:translate-x-0 overflow-y-auto ${isSidebarOpen ? 'translate-x-0' : '-translate-x-full'}`}>
                <div className="flex flex-col h-full">
                    {/* Brand */}
                    <div className="p-8 pb-4">
                        <div className="flex items-center space-x-3 mb-2">
                            <div className="relative group">
                                <div className="absolute -inset-1 bg-gradient-to-r from-indigo-500 to-blue-600 rounded-xl blur opacity-25 group-hover:opacity-50 transition duration-1000"></div>
                                <div className="relative p-2 bg-indigo-600 rounded-xl text-white shadow-lg shadow-indigo-200">
                                    <Shield size={24} strokeWidth={2.5} />
                                </div>
                            </div>
                            <div>
                                <h1 className="text-xl font-black tracking-tight text-zinc-900 leading-none">kprotect</h1>
                                <p className="text-[10px] font-bold text-indigo-600 uppercase tracking-widest mt-1">Enterprise Shield</p>
                            </div>
                        </div>
                    </div>

                    {/* Navigation */}
                    <nav className="flex-1 px-4 py-8 space-y-8">
                        {hubGroups.map((hub) => (
                            <div key={hub} className="space-y-1">
                                <h3 className="px-4 text-[10px] font-black text-zinc-400 uppercase tracking-[0.2em] mb-4">{hub}</h3>
                                {sidebarItems.filter(item => item.hub === hub).map((item) => (
                                    <button
                                        key={item.id}
                                        onClick={() => {
                                            setActiveTab(item.id);
                                            setIsSidebarOpen(false);
                                        }}
                                        className={`w-full flex items-center space-x-3 px-4 py-3 rounded-xl text-sm font-bold transition-all duration-200 group ${activeTab === item.id
                                            ? 'bg-zinc-900 text-white shadow-xl shadow-zinc-200 translate-x-1'
                                            : 'text-zinc-500 hover:text-zinc-900 hover:bg-zinc-50'
                                            }`}
                                    >
                                        <span className={`${activeTab === item.id ? 'text-indigo-400' : 'text-zinc-400 group-hover:text-zinc-600'}`}>
                                            {item.icon}
                                        </span>
                                        <span className="flex-1 text-left">{item.label}</span>
                                        {activeTab === item.id && (
                                            <div className="w-1.5 h-1.5 rounded-full bg-indigo-400 shadow-sm shadow-indigo-400/50" />
                                        )}
                                    </button>
                                ))}
                            </div>
                        ))}
                    </nav>
                </div>
            </aside>

            {/* Backdrop */}
            {isSidebarOpen && (
                <div
                    className="fixed inset-0 bg-zinc-900/40 backdrop-blur-sm z-40 lg:hidden"
                    onClick={() => setIsSidebarOpen(false)}
                />
            )}

            {/* Main */}
            <main className="flex-1 flex flex-col bg-white min-w-0 h-screen overflow-y-auto">
                <header className="h-16 flex items-center justify-between px-4 sm:px-8 border-b border-zinc-200 bg-white sticky top-0 z-30 shrink-0">
                    <div className="flex items-center">
                        <button
                            onClick={() => setIsSidebarOpen(true)}
                            className="lg:hidden p-2 mr-2 -ml-2 hover:bg-zinc-100 rounded-lg text-zinc-600 transition-colors"
                        >
                            <Menu size={20} />
                        </button>
                        <h2 className="text-lg sm:text-xl font-semibold text-zinc-900 tracking-tight truncate">{title}</h2>
                    </div>

                    <div className="flex items-center space-x-2 sm:space-x-4">
                        {!isRootActive ? (
                            <button
                                onClick={handleTriggerRoot}
                                className="flex items-center px-4 py-2 rounded-xl text-xs font-bold text-white bg-indigo-600 hover:bg-indigo-700 transition-all shadow-lg shadow-indigo-200 active:scale-95"
                            >
                                <Zap size={14} className="sm:mr-2" fill="currentColor" />
                                <span className="hidden sm:inline">Trigger Root</span>
                            </button>
                        ) : (
                            <div className="flex items-center space-x-2">
                                <span className="hidden sm:flex items-center px-3 py-2 rounded-xl text-xs font-bold text-emerald-700 bg-emerald-50 border border-emerald-200 shadow-sm">
                                    <CheckCircle size={14} className="mr-2" /> Root Granted
                                </span>
                                <button
                                    onClick={handleStopRoot}
                                    className="p-2 sm:px-4 sm:py-2 rounded-xl text-xs font-bold text-rose-600 bg-rose-50 hover:bg-rose-100 border border-rose-200 transition-all active:scale-95"
                                    title="Stop Root Session"
                                >
                                    <Power size={14} className="sm:mr-2" />
                                    <span className="hidden sm:inline">Stop</span>
                                </button>
                            </div>
                        )}
                    </div>
                </header>

                <div className="p-4 sm:p-8">
                    <div className="max-w-6xl mx-auto">
                        {children}
                    </div>
                </div>
            </main>
        </div>
    );
}

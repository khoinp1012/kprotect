import { ReactNode, useState } from 'react';
import { List, Settings, Menu, Zap, CheckCircle, Power, Layers, Code2, LayoutDashboard, Bell, X } from "lucide-react";
import { useGlobal } from '../context/GlobalContext';
import { api } from '../api';
import { toast } from 'sonner';

interface LayoutProps {
    children: ReactNode;
    activeTab: string;
    setActiveTab: (tab: any) => void;
    title: string;
}

export function Layout({ children, activeTab, setActiveTab, title }: LayoutProps) {
    const { isConnected, isRootActive, allowlistCount, events, checkRootStatus, refreshAllowlist } = useGlobal();
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

            // Poll for status (wait for password entry, up to 60s)
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
        } catch (e: any) {
            // Toast handled above
        }
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

    const navItems = [
        { id: 'dashboard', label: 'Dashboard', icon: <LayoutDashboard size={20} /> },
        { id: 'events', label: 'Live Feed', icon: <List size={20} />, badge: events.length > 0 ? events.length.toString() : undefined },
        { id: 'allowlist', label: 'Allowlist', icon: <CheckCircle size={20} />, badge: allowlistCount > 0 ? allowlistCount.toString() : undefined },
        { id: 'notifications', label: 'Notifications', icon: <Bell size={20} /> },
    ];

    const policyItems = [
        { id: 'zones', label: 'Security Zones', icon: <Layers size={20} /> },
        { id: 'enrichment', label: 'Interpreters', icon: <Code2 size={20} /> },
    ];


    const handleNavClick = (id: string) => {
        setActiveTab(id);
        setIsSidebarOpen(false);
    };

    return (
        <div className="flex min-h-screen bg-white text-zinc-900 font-sans selection:bg-indigo-500/30">
            {/* Sidebar (Drawer on mobile) */}
            <aside
                className={`fixed inset-y-0 left-0 z-50 w-72 bg-zinc-50 border-r border-zinc-200 transform transition-transform duration-300 ease-in-out lg:sticky lg:top-0 lg:h-screen lg:translate-x-0 ${isSidebarOpen ? 'translate-x-0' : '-translate-x-full'
                    } flex flex-col`}
            >
                <div className="p-6">
                    <div className="flex items-center justify-between mb-8 px-2">
                        <div className="flex items-center space-x-3">
                            <div className="w-10 h-10 rounded-lg shadow-sm overflow-hidden bg-indigo-600 flex items-center justify-center">
                                <img src="/logo.png" alt="kprotect logo" className="w-full h-full object-cover" />
                            </div>
                            <div>
                                <h1 className="text-lg font-bold text-zinc-900 tracking-tight">kprotect</h1>
                                <div className="flex items-center space-x-2 mt-0.5">
                                    <div className={`w-1.5 h-1.5 rounded-full ${isConnected ? 'bg-emerald-500' : 'bg-rose-500'}`}></div>
                                    <span className="text-[10px] font-bold text-zinc-500 tracking-wider uppercase">
                                        {isConnected ? 'Online' : 'Offline'}
                                    </span>
                                </div>
                            </div>
                        </div>
                        <button onClick={() => setIsSidebarOpen(false)} className="lg:hidden p-2 hover:bg-zinc-200 rounded-lg text-zinc-600">
                            <X size={20} />
                        </button>
                    </div>

                    <nav className="space-y-1">
                        {navItems.map(item => (
                            <NavItem
                                key={item.id}
                                active={activeTab === item.id}
                                onClick={() => handleNavClick(item.id)}
                                icon={item.icon}
                                label={item.label}
                                badge={item.badge}
                            />
                        ))}

                        <div className="my-6 border-t border-zinc-200 mx-2"></div>
                        <span className="px-3 text-[10px] font-bold text-zinc-500 uppercase tracking-widest block mb-2">Policy Configuration</span>
                        {policyItems.map(item => (
                            <NavItem
                                key={item.id}
                                active={activeTab === item.id}
                                onClick={() => handleNavClick(item.id)}
                                icon={item.icon}
                                label={item.label}
                            />
                        ))}

                    </nav>
                </div>
                <div className="mt-auto p-4 border-t border-zinc-200">
                    <NavItem active={activeTab === 'settings'} onClick={() => handleNavClick('settings')} icon={<Settings size={20} />} label="Settings" />
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

function NavItem({ active, onClick, icon, label, badge }: any) {
    return (
        <button
            onClick={onClick}
            className={`w-full flex items-center px-3 py-2.5 rounded-xl transition-all duration-200 group relative ${active
                ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-100'
                : 'text-zinc-500 hover:bg-zinc-100 hover:text-zinc-900'
                }`}
        >
            <div className="flex items-center space-x-3">
                <span className={`${active ? 'text-white' : 'text-zinc-400 group-hover:text-zinc-600'}`}>
                    {icon}
                </span>
                <span className="text-sm font-bold tracking-tight">{label}</span>
            </div>
            {badge && (
                <span className={`ml-auto px-1.5 py-0.5 rounded-lg text-[10px] font-bold ${active ? 'bg-white/20 text-white' : 'bg-zinc-200 text-zinc-600'}`}>
                    {badge}
                </span>
            )}
        </button>
    );
}

import { useState, useEffect, useMemo, Fragment } from 'react';
import { Activity, Plus, Trash2, Key, Search, X, ShieldCheck, ChevronRight } from 'lucide-react';
import { api } from '../api';
import { SudoRule, Event } from '../types';
import { useGlobal } from '../context/GlobalContext';
import { toast } from 'sonner';
import { ContextualUnlock } from '../components/ContextualUnlock';
import { StatusBadge } from '../components/EventList';

interface QuickSudoProps {
    initialTab?: 'rules' | 'feed' | 'history';
}

export function QuickSudo({ initialTab = 'feed' }: QuickSudoProps = {}) {
    const { isRootActive, elevationEvents } = useGlobal();
    const [activeTab, setActiveTab] = useState<'rules' | 'feed'>(initialTab === 'history' ? 'feed' : initialTab);
    const [rules, setRules] = useState<SudoRule[]>([]);
    const [selectedEventId, setSelectedEventId] = useState<number | string | null>(null);

    const [loading, setLoading] = useState(true);
    const [searchTerm, setSearchTerm] = useState('');

    // Auth Modal State
    const [authModalOpen, setAuthModalOpen] = useState(false);
    const [selectedEvent, setSelectedEvent] = useState<Event | null>(null);
    const [authDesc, setAuthDesc] = useState('');

    useEffect(() => {
        if (activeTab === 'rules') loadRules();
    }, [activeTab, isRootActive]);

    const loadRules = async () => {
        setLoading(true);
        try {
            const [r] = await Promise.all([
                api.getSudoRules()
            ]);
            setRules(r);
        } catch (e) {
            console.error('Failed to load rules:', e);
        } finally {
            setLoading(false);
        }
    };



    const filteredElevationEvents = useMemo(() => {
        const term = searchTerm.toLowerCase();
        return elevationEvents.filter(e =>
            e.pid.toString().includes(term) ||
            e.status.toLowerCase().includes(term) ||
            e.chain.some(p => p.toLowerCase().includes(term))
        );
    }, [elevationEvents, searchTerm]);

    const openAuthModal = (event: Event) => {
        setSelectedEvent(event);
        const basename = event.chain[event.chain.length - 1].split('/').pop() || "Process";
        setAuthDesc(`Allow sudo bypass for ${basename}`);
        setAuthModalOpen(true);
    };

    const submitAuth = async () => {
        if (!selectedEvent) return;
        toast.promise(
            async () => {
                await api.addSudoRule(selectedEvent.chain, authDesc);
                await loadRules();
                setAuthModalOpen(false);
            },
            { loading: 'Authorizing...', success: 'Rule authorized', error: (e) => `Failed: ${e}` }
        );
    };

    const handleAddRule = async () => {
        // Simple prompt for now, could be a modal
        const patternStr = prompt("Enter process lineage (comma separated paths):");
        if (!patternStr) return;
        const description = prompt("Enter rule description:");
        if (!description) return;

        const pattern = patternStr.split(',').map(s => s.trim());

        toast.promise(
            async () => {
                await api.addSudoRule(pattern, description);
                await loadRules();
            },
            { loading: 'Adding sudo rule...', success: 'Rule added', error: (e) => `Failed: ${e}` }
        );
    };



    const handleDeleteRule = async (pattern: string[]) => {
        if (!confirm(`Are you sure you want to remove the rule for:\n\n${pattern.join(" -> ")}`)) return;

        toast.promise(
            async () => {
                await api.removeSudoRule(pattern);
                await loadRules();
            },
            { loading: 'Removing rule...', success: 'Rule removed', error: (e) => `Failed: ${e}` }
        );
    };

    const tabs = [
        { id: 'feed', label: 'Elevation Live Feed', icon: <Activity size={16} /> },
        { id: 'rules', label: 'Elevation Allow List', icon: <Key size={16} /> },
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

            {!isRootActive && activeTab === 'rules' && (
                <ContextualUnlock description="Managing quick sudo rules requires an active root session." />
            )}

            <div className="animate-in fade-in slide-in-from-bottom-4 duration-300">
                {activeTab === 'rules' && (
                    <div className="space-y-4">
                        <div className="flex justify-between items-center px-1">
                            <h3 className="text-sm font-bold text-zinc-400 uppercase tracking-widest">Quick Sudo Rules</h3>
                            <div className="flex items-center space-x-3">
                                <div className="flex items-center space-x-1 border-r border-zinc-200 pr-3 mr-1">
                                    {/* Notifications moved to System Config */}
                                </div>
                                <button
                                    onClick={handleAddRule}
                                    disabled={!isRootActive}
                                    className="flex items-center space-x-2 px-3 py-1.5 bg-indigo-600 text-white rounded-lg text-xs font-bold hover:bg-indigo-700 transition-all disabled:opacity-50"
                                >
                                    <Plus size={14} />
                                    <span>Add Rule</span>
                                </button>
                            </div>
                        </div>
                        <div className="bg-white border border-zinc-200 rounded-xl overflow-hidden shadow-sm">
                            <table className="w-full text-left text-sm text-zinc-600">
                                <thead className="bg-zinc-50 text-zinc-500 uppercase text-[10px] font-bold tracking-wider border-b border-zinc-200">
                                    <tr>
                                        <th className="px-6 py-3">Process Chain</th>
                                        <th className="px-6 py-3">Purpose</th>
                                        <th className="px-6 py-3">Status</th>
                                        <th className="px-6 py-3 text-right">Actions</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-zinc-100">
                                    {rules.map((rule, idx) => (
                                        <tr key={idx} className="hover:bg-zinc-50/50 transition-colors">
                                            <td className="px-6 py-4">
                                                <div className="flex flex-wrap gap-1">
                                                    {rule.pattern.map((p, i) => (
                                                        <span key={i} className="font-mono text-[10px] bg-zinc-100 px-1.5 py-0.5 rounded border border-zinc-200 transition-colors" title={p}>
                                                            {p.split('/').pop()}
                                                            {i < rule.pattern.length - 1 && " →"}
                                                        </span>
                                                    ))}
                                                </div>
                                            </td>
                                            <td className="px-6 py-4 text-xs font-medium text-zinc-700">{rule.description}</td>
                                            <td className="px-6 py-4">
                                                <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${rule.enabled ? 'bg-emerald-50 text-emerald-600 border border-emerald-100' : 'bg-zinc-50 text-zinc-500 border border-zinc-200'}`}>
                                                    {rule.enabled ? "Active" : "Disabled"}
                                                </span>
                                            </td>
                                            <td className="px-6 py-4 text-right">
                                                <button
                                                    onClick={() => handleDeleteRule(rule.pattern)}
                                                    disabled={!isRootActive}
                                                    className="text-rose-600 hover:text-rose-700 p-1.5 rounded-lg hover:bg-rose-50 transition-all disabled:opacity-50 disabled:cursor-not-allowed">
                                                    <Trash2 size={14} />
                                                </button>
                                            </td>
                                        </tr>
                                    ))}
                                    {rules.length === 0 && !loading && (
                                        <tr>
                                            <td colSpan={4} className="px-6 py-12 text-center text-zinc-400 italic text-sm">No sudo rules defined.</td>
                                        </tr>
                                    )}
                                </tbody>
                            </table>
                        </div>
                    </div>
                )}

                {activeTab === 'feed' && (
                    <div className="space-y-4">
                        <div className="bg-white border border-zinc-200 rounded-xl overflow-hidden shadow-sm">
                            {/* Toolbar */}
                            <div className="px-5 py-4 border-b border-zinc-200 flex flex-col sm:flex-row justify-between items-start sm:items-center bg-white space-y-3 sm:space-y-0">
                                <div className="flex items-center space-x-3">
                                    <div className="p-2 bg-indigo-50 rounded-lg">
                                        <Activity size={18} className="text-indigo-600" />
                                    </div>
                                    <div>
                                        <h3 className="text-sm font-bold text-zinc-900 leading-none">Elevation Logs</h3>
                                        <p className="text-[10px] text-zinc-500 mt-1 uppercase tracking-wider font-semibold">Quick Sudo Live Feed</p>
                                    </div>
                                </div>

                                <div className="flex items-center space-x-2 w-full sm:w-auto">
                                    <div className="relative flex-1 sm:flex-none">
                                        <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-400" />
                                        <input
                                            type="text"
                                            placeholder="Search..."
                                            value={searchTerm}
                                            onChange={(e) => setSearchTerm(e.target.value)}
                                            className="w-full sm:w-48 pl-9 pr-3 py-1.5 rounded-lg text-xs font-medium text-zinc-700 border border-zinc-300 focus:outline-none focus:ring-2 focus:ring-indigo-500/10 focus:border-indigo-500 transition-all"
                                        />
                                    </div>
                                </div>
                            </div>

                            <div className="hidden md:block overflow-x-auto">
                                <table className="w-full text-left text-sm text-zinc-600">
                                    <thead className="bg-zinc-50 text-zinc-500 uppercase text-[11px] font-semibold tracking-wider border-b border-zinc-200">
                                        <tr>
                                            <th className="px-6 py-3">Time</th>
                                            <th className="px-6 py-3">Status</th>
                                            <th className="px-6 py-3">PID</th>
                                            <th className="px-6 py-3">Source (PAM)</th>
                                            <th className="px-6 py-3">Process Chain</th>
                                            <th className="px-6 py-3 text-right">Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y divide-zinc-100">
                                        {filteredElevationEvents.map((ev, idx) => (
                                            <Fragment key={idx}>
                                                <tr
                                                    onClick={() => setSelectedEventId(prev => prev === (ev.id || idx) ? null : (ev.id || idx))}
                                                    className={`transition-colors group cursor-pointer ${selectedEventId === (ev.id || idx) ? 'bg-indigo-50/50' : 'hover:bg-zinc-50/80'}`}
                                                >
                                                    <td className="px-6 py-4 text-[10px] font-mono whitespace-nowrap align-top text-zinc-400">
                                                        <div className="flex flex-col">
                                                            <span>#{ev.id || idx}</span>
                                                            <span className="text-[10px] text-zinc-500 mt-1">
                                                                {new Date(ev.timestamp).toLocaleTimeString()}
                                                            </span>
                                                        </div>
                                                    </td>
                                                    <td className="px-6 py-4 align-top w-32">
                                                        <StatusBadge originalStatus={ev.status === 'Elevation' ? 'Verified' : 'Blocked'} />
                                                    </td>
                                                    <td className="px-6 py-4 font-mono text-zinc-500 text-xs align-top w-20">{ev.pid}</td>
                                                    <td className="px-6 py-4 align-top max-w-[200px]">
                                                        <div className="flex items-center space-x-2">
                                                            <ShieldCheck size={14} className="text-indigo-400 shrink-0" />
                                                            <span className="font-mono text-[11px] text-zinc-700 break-all bg-indigo-50/30 px-1.5 py-0.5 rounded border border-indigo-100/50">
                                                                Sudo Bypass Hook
                                                            </span>
                                                        </div>
                                                    </td>
                                                    <td className="px-6 py-4 align-top">
                                                        <div className="flex flex-wrap items-center gap-1.5">
                                                            {ev.chain.map((p, i) => (
                                                                <div key={i} className="flex items-center">
                                                                    <span className={`font-mono text-[10px] px-1.5 py-0.5 rounded border ${i === ev.chain.length - 1
                                                                        ? 'bg-zinc-100 text-zinc-900 border-zinc-300 font-bold'
                                                                        : 'bg-zinc-50 text-zinc-500 border-zinc-200'
                                                                        }`} title={p}>
                                                                        {p.split('/').pop()}
                                                                    </span>
                                                                    {i < ev.chain.length - 1 && <ChevronRight size={10} className="text-zinc-300 mx-0.5" />}
                                                                </div>
                                                            ))}
                                                        </div>
                                                    </td>
                                                    <td className="px-6 py-4 text-right align-top w-40 sticky right-0 bg-white group-hover:bg-zinc-50/80 transition-colors z-10" onClick={(e) => e.stopPropagation()}>
                                                        {ev.status !== 'Elevation' && (
                                                            <div className="flex flex-col items-end space-y-1">
                                                                <button
                                                                    onClick={() => openAuthModal(ev)}
                                                                    disabled={!isRootActive || !ev.complete}
                                                                    className="flex items-center space-x-1 px-2 py-1 bg-indigo-50 text-indigo-600 rounded-lg hover:bg-indigo-100 transition-colors disabled:opacity-40 disabled:bg-zinc-50 disabled:text-zinc-400 disabled:cursor-not-allowed ml-auto border border-indigo-100 font-bold"
                                                                    title={!ev.complete ? "Cannot authorize: Incomplete lineage chain. A full system reboot is required." : ""}
                                                                >
                                                                    <Plus size={12} />
                                                                    <span className="text-[10px] uppercase">Authorize</span>
                                                                </button>
                                                                {!ev.complete && (
                                                                    <span className="text-[9px] text-rose-500 font-bold uppercase tracking-tighter">Requires Reboot</span>
                                                                )}
                                                            </div>
                                                        )}
                                                    </td>
                                                </tr>
                                                {selectedEventId === (ev.id || idx) && (
                                                    <tr className="bg-zinc-50/50">
                                                        <td colSpan={6} className="px-6 py-4 border-t border-zinc-100">
                                                            <div className="bg-white p-4 rounded-xl border border-zinc-200 shadow-sm">
                                                                <h4 className="text-[10px] font-bold text-zinc-400 uppercase tracking-wider mb-3">Full Elevation Chain Detail</h4>
                                                                <div className="flex flex-wrap items-center gap-2 p-3 bg-zinc-50/50 rounded-lg border border-zinc-100">
                                                                    {ev.chain.map((proc, i) => (
                                                                        <div key={i} className="flex items-center">
                                                                            <div className={`px-2 py-1 rounded-md text-[11px] font-mono border ${i === ev.chain.length - 1
                                                                                ? 'bg-indigo-50 border-indigo-200 text-indigo-900 font-bold'
                                                                                : 'bg-white border-zinc-200 text-zinc-600'
                                                                                }`}>
                                                                                {proc}
                                                                            </div>
                                                                            {i < ev.chain.length - 1 && (
                                                                                <ChevronRight size={12} className="text-zinc-300 mx-2" />
                                                                            )}
                                                                        </div>
                                                                    ))}
                                                                </div>
                                                            </div>
                                                        </td>
                                                    </tr>
                                                )}
                                            </Fragment>
                                        ))}
                                        {filteredElevationEvents.length === 0 && (
                                            <tr>
                                                <td colSpan={6} className="p-12 text-center">
                                                    <Activity className="mx-auto text-zinc-200 mb-4" size={32} />
                                                    <p className="text-zinc-500 text-sm font-medium">No elevation logs found...</p>
                                                    <p className="text-[10px] text-zinc-400 uppercase tracking-widest mt-1">Real-time stream from PAM Hook</p>
                                                </td>
                                            </tr>
                                        )}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                )}


            </div>

            {/* Sudo Auth Modal */}
            {authModalOpen && selectedEvent && (
                <div className="fixed inset-0 bg-zinc-900/60 backdrop-blur-sm flex items-end sm:items-center justify-center z-50 p-0 sm:p-4">
                    <div className="bg-white rounded-t-2xl sm:rounded-2xl shadow-2xl w-full max-w-lg p-6 animate-in slide-in-from-bottom-full sm:slide-in-from-bottom-4 duration-300">
                        <div className="flex justify-between items-center mb-6">
                            <h3 className="text-lg font-bold text-zinc-900 flex items-center">
                                <Key className="mr-2 text-indigo-600" size={20} />
                                Authorize Quick Sudo
                            </h3>
                            <button onClick={() => setAuthModalOpen(false)} className="p-2 hover:bg-zinc-100 rounded-full transition-colors">
                                <X size={20} className="text-zinc-400" />
                            </button>
                        </div>

                        <div className="space-y-6">
                            <div>
                                <label className="block text-xs font-bold text-zinc-400 uppercase tracking-wider mb-2">Process Lineage</label>
                                <div className="bg-zinc-50 p-4 rounded-xl text-[11px] font-mono text-zinc-600 border border-zinc-200 max-h-40 overflow-y-auto">
                                    {selectedEvent.chain.map((c, i) => (
                                        <div key={i} className="flex items-center space-x-2 py-0.5">
                                            <span className="text-zinc-300">↳</span>
                                            <span>{c}</span>
                                        </div>
                                    ))}
                                </div>
                                <div className="mt-4 p-3 bg-indigo-50/50 border border-indigo-100 rounded-xl">
                                    <div className="flex items-start space-x-2.5">
                                        <ShieldCheck size={16} className="text-indigo-600 mt-0.5 shrink-0" />
                                        <div>
                                            <p className="text-[11px] font-bold text-indigo-900 uppercase tracking-tight">Quick Sudo Scope</p>
                                            <p className="text-[11px] text-indigo-700/80 leading-relaxed font-medium mt-0.5">
                                                This grants the process chain permission to bypass sudo password prompts.
                                            </p>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            <div className="space-y-4">
                                <div>
                                    <label className="block text-xs font-bold text-zinc-400 uppercase tracking-wider mb-2">Rule Purpose</label>
                                    <input
                                        type="text"
                                        value={authDesc}
                                        onChange={(e) => setAuthDesc(e.target.value)}
                                        className="w-full px-4 py-3 rounded-xl border border-zinc-300 focus:outline-none focus:ring-4 focus:ring-indigo-500/10 focus:border-indigo-500 text-sm transition-all"
                                        placeholder="Enter description (e.g., Allow IDE to run as root)"
                                    />
                                </div>
                                <div className="flex flex-col sm:flex-row space-y-2 sm:space-y-0 sm:space-x-3">
                                    <button
                                        onClick={() => setAuthModalOpen(false)}
                                        className="flex-1 px-4 py-3 text-sm font-bold text-zinc-600 bg-zinc-100 hover:bg-zinc-200 rounded-xl transition-all"
                                    >
                                        Cancel
                                    </button>
                                    <button
                                        onClick={submitAuth}
                                        className="flex-[2] px-4 py-3 text-sm font-bold text-white bg-indigo-600 hover:bg-indigo-700 rounded-xl shadow-lg shadow-indigo-200 transition-all"
                                    >
                                        Confirm Access
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}

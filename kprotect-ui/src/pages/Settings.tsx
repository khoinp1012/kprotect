import { useState, useEffect, useRef, useCallback } from 'react';
import { api } from '../api';
import { Save, History, Shield, Clock, CheckCircle2, AlertCircle, RefreshCw, User } from 'lucide-react';
import { toast } from 'sonner';
import { useGlobal } from '../context/GlobalContext';

import { ContextualUnlock } from '../components/ContextualUnlock';

export function Settings() {
    const { isRootActive, auditLogs, loadMoreAuditLogs, refreshAuditLogs } = useGlobal();
    const [loading, setLoading] = useState(false);
    const [saving, setSaving] = useState(false);
    const [loadingMore, setLoadingMore] = useState(false);

    const [eventsRetention, setEventsRetention] = useState(30);
    const [auditRetention, setAuditRetention] = useState(90);

    // Infinite Scroll Intersection Observer
    const observer = useRef<IntersectionObserver | null>(null);
    const lastElementRef = useCallback((node: HTMLDivElement | HTMLTableRowElement | null) => {
        if (loadingMore) return;
        if (observer.current) observer.current.disconnect();

        observer.current = new IntersectionObserver(entries => {
            if (entries[0].isIntersecting && auditLogs.length >= 20) {
                setLoadingMore(true);
                loadMoreAuditLogs().finally(() => setLoadingMore(false));
            }
        });

        if (node) observer.current.observe(node);
    }, [loadingMore, loadMoreAuditLogs, auditLogs.length]);

    useEffect(() => {
        loadConfig();
    }, []);

    const loadConfig = async () => {
        setLoading(true);
        try {
            const cfg = await api.getLogConfig();
            setEventsRetention(cfg.event_log_retention_days);
            setAuditRetention(cfg.audit_log_retention_days);
        } catch (e) {
            console.error(e);
            toast.error("Failed to load settings");
        } finally {
            setLoading(false);
        }
    };

    const handleSave = async () => {
        if (!isRootActive) {
            toast.error("Root session required to change settings");
            return;
        }

        setSaving(true);
        try {
            await api.setLogRetention(eventsRetention, auditRetention);
            toast.success("Log retention updated");
            await loadConfig();
        } catch (e) {
            toast.error(`Save failed: ${e}`);
        } finally {
            setSaving(false);
        }
    };

    if (loading) {
        return <div className="p-8 text-center text-zinc-500">Loading settings...</div>;
    }

    return (
        <div className="space-y-12 pb-20">
            {/* Retention Settings */}
            <section className="animate-in fade-in slide-in-from-bottom-4 duration-500">
                <div className="flex items-center space-x-3 mb-6 px-1">
                    <div className="p-2.5 bg-indigo-50 text-indigo-600 rounded-xl shadow-sm">
                        <Shield size={22} />
                    </div>
                    <div>
                        <h3 className="text-lg font-bold text-zinc-900 tracking-tight">Governance & Retention</h3>
                        <p className="text-sm text-zinc-500 font-medium">Control how long security data is persisted on disk.</p>
                    </div>
                </div>

                <div className="bg-white border border-zinc-200 rounded-2xl overflow-hidden shadow-sm">
                    <div className="p-6 sm:p-8 space-y-10">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-10">
                            <div className="space-y-4">
                                <label className="text-sm font-bold text-zinc-700 flex items-center uppercase tracking-wider">
                                    <Clock size={16} className="mr-2 text-zinc-400" />
                                    Security Event Retention
                                </label>
                                <div className="space-y-4">
                                    <input
                                        type="range" min="1" max="365"
                                        value={eventsRetention}
                                        onChange={(e) => setEventsRetention(parseInt(e.target.value))}
                                        className="w-full h-2 bg-zinc-100 rounded-lg appearance-none cursor-pointer accent-indigo-600"
                                    />
                                    <div className="flex justify-between items-center bg-zinc-50 p-4 rounded-xl border border-zinc-100">
                                        <span className="text-xs font-bold text-zinc-500 uppercase tracking-widest">Selected Period</span>
                                        <span className="text-xl font-mono font-bold text-indigo-600">{eventsRetention} days</span>
                                    </div>
                                </div>
                                <p className="text-xs text-zinc-400 font-medium px-1">Days to keep raw process execution events (e.g. execve, fork).</p>
                            </div>

                            <div className="space-y-4">
                                <label className="text-sm font-bold text-zinc-700 flex items-center uppercase tracking-wider">
                                    <Clock size={16} className="mr-2 text-zinc-400" />
                                    Audit Log Retention
                                </label>
                                <div className="space-y-4">
                                    <input
                                        type="range" min="1" max="730"
                                        value={auditRetention}
                                        onChange={(e) => setAuditRetention(parseInt(e.target.value))}
                                        className="w-full h-2 bg-zinc-100 rounded-lg appearance-none cursor-pointer accent-indigo-600"
                                    />
                                    <div className="flex justify-between items-center bg-zinc-50 p-4 rounded-xl border border-zinc-100">
                                        <span className="text-xs font-bold text-zinc-500 uppercase tracking-widest">Selected Period</span>
                                        <span className="text-xl font-mono font-bold text-indigo-600">{auditRetention} days</span>
                                    </div>
                                </div>
                                <p className="text-xs text-zinc-400 font-medium px-1">Days to keep administrative action logs (e.g. rule changes, root access).</p>
                            </div>
                        </div>

                        {!isRootActive && (
                            <ContextualUnlock
                                description="Changing log retention settings requires an active root session. Unlock to enable modifications."
                            />
                        )}
                    </div>
                    <div className="px-6 py-5 bg-zinc-50/50 border-t border-zinc-100 flex justify-end">
                        <button
                            onClick={handleSave}
                            disabled={saving || !isRootActive}
                            className="flex items-center px-6 py-2.5 bg-indigo-600 text-white rounded-xl font-bold text-sm hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-lg shadow-indigo-200 active:scale-95"
                        >
                            <Save size={18} className="mr-2" />
                            {saving ? "Saving..." : "Apply Changes"}
                        </button>
                    </div>
                </div>
            </section>

            {/* Audit History */}
            <section className="animate-in fade-in slide-in-from-bottom-4 duration-500 delay-150">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between mb-6 px-1 gap-4">
                    <div className="flex items-center space-x-3">
                        <div className="p-2.5 bg-zinc-100 text-zinc-600 rounded-xl shadow-sm">
                            <History size={22} />
                        </div>
                        <div>
                            <h3 className="text-lg font-bold text-zinc-900 tracking-tight">Administrative Audit</h3>
                            <p className="text-sm text-zinc-500 font-medium">Immutable history of privileged commands.</p>
                        </div>
                    </div>
                    <button
                        onClick={() => {
                            loadConfig();
                            refreshAuditLogs();
                        }}
                        className="flex items-center justify-center space-x-2 px-4 py-2 text-xs font-bold text-indigo-600 hover:bg-indigo-50 border border-indigo-100 rounded-xl transition-all w-full sm:w-auto"
                    >
                        <RefreshCw size={14} />
                        <span>Refresh Logs</span>
                    </button>
                </div>

                <div className="bg-white border border-zinc-200 rounded-2xl overflow-hidden shadow-sm">
                    {/* Mobile Card Layout */}
                    <div className="md:hidden divide-y divide-zinc-100">
                        {auditLogs.length === 0 ? (
                            <div className="p-10 text-center text-zinc-400 text-sm italic">No audit history found.</div>
                        ) : (
                            auditLogs.map((log, idx) => (
                                <div
                                    key={idx}
                                    ref={idx === auditLogs.length - 1 ? lastElementRef : null}
                                    className="p-5 active:bg-zinc-50 transition-colors"
                                >
                                    <div className="flex justify-between items-start mb-3">
                                        <div className="flex items-center space-x-2">
                                            <div className="p-1.5 bg-zinc-100 rounded-lg">
                                                <User size={14} className="text-zinc-600" />
                                            </div>
                                            <span className="text-sm font-bold text-zinc-900">{log.username}</span>
                                        </div>
                                        {log.success ? (
                                            <span className="flex items-center text-[10px] font-bold text-emerald-600 bg-emerald-50 px-2 py-0.5 rounded-full border border-emerald-100">
                                                <CheckCircle2 size={10} className="mr-1" /> Success
                                            </span>
                                        ) : (
                                            <span className="flex items-center text-[10px] font-bold text-rose-600 bg-rose-50 px-2 py-0.5 rounded-full border border-rose-100">
                                                <AlertCircle size={10} className="mr-1" /> Failed
                                            </span>
                                        )}
                                    </div>
                                    <div className="space-y-2">
                                        <p className="text-sm font-bold text-indigo-700">{log.action}</p>
                                        <div className="text-[11px] font-mono text-zinc-500 bg-zinc-50 p-2 rounded-lg border border-zinc-100 break-all">
                                            {typeof log.details === 'string' ? log.details : JSON.stringify(log.details)}
                                        </div>
                                        <div className="flex items-center text-[10px] text-zinc-400 font-medium pt-1">
                                            <Clock size={10} className="mr-1.5" />
                                            {log.timestamp ? new Date(log.timestamp * 1000).toLocaleString([], {
                                                year: 'numeric', month: 'short', day: '2-digit',
                                                hour: '2-digit', minute: '2-digit', hour12: false
                                            }) : 'N/A'}
                                        </div>
                                    </div>
                                </div>
                            ))
                        )}
                    </div>

                    {/* Desktop Table Layout */}
                    <div className="hidden md:block overflow-x-auto">
                        <table className="w-full text-left border-collapse">
                            <thead>
                                <tr className="bg-zinc-50 border-b border-zinc-200">
                                    <th className="px-6 py-4 text-[11px] font-bold text-zinc-500 uppercase tracking-widest">Time</th>
                                    <th className="px-6 py-4 text-[11px] font-bold text-zinc-500 uppercase tracking-widest">User</th>
                                    <th className="px-6 py-4 text-[11px] font-bold text-zinc-500 uppercase tracking-widest">Action</th>
                                    <th className="px-6 py-4 text-[11px] font-bold text-zinc-500 uppercase tracking-widest text-right">Status</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-zinc-100">
                                {auditLogs.length === 0 ? (
                                    <tr>
                                        <td colSpan={4} className="px-6 py-12 text-center text-zinc-400 text-sm italic">No audit history found.</td>
                                    </tr>
                                ) : (
                                    auditLogs.map((log, idx) => (
                                        <tr
                                            key={idx}
                                            ref={idx === auditLogs.length - 1 ? lastElementRef : null}
                                            className="hover:bg-zinc-50/50 transition-colors group"
                                        >
                                            <td className="px-6 py-4 text-xs text-zinc-500 font-mono">
                                                {log.timestamp ? new Date(log.timestamp * 1000).toLocaleString([], {
                                                    year: 'numeric', month: 'numeric', day: 'numeric',
                                                    hour: '2-digit', minute: '2-digit', second: '2-digit',
                                                    hour12: false
                                                }) : 'N/A'}
                                            </td>
                                            <td className="px-6 py-4">
                                                <div className="flex items-center">
                                                    <div className="w-7 h-7 bg-zinc-100 rounded-lg flex items-center justify-center mr-3 group-hover:bg-zinc-200 transition-colors">
                                                        <User size={14} className="text-zinc-600" />
                                                    </div>
                                                    <span className="text-sm font-bold text-zinc-700">{log.username}</span>
                                                </div>
                                            </td>
                                            <td className="px-6 py-4">
                                                <div className="text-sm font-bold text-zinc-900 mb-1">{log.action}</div>
                                                <div className="text-[11px] font-mono text-zinc-400 truncate max-w-sm group-hover:text-zinc-500">
                                                    {typeof log.details === 'string' ? log.details : JSON.stringify(log.details)}
                                                </div>
                                            </td>
                                            <td className="px-6 py-4 text-right">
                                                {log.success ? (
                                                    <span className="inline-flex items-center px-2.5 py-1 rounded-full text-[10px] font-bold bg-emerald-50 text-emerald-700 border border-emerald-100 shadow-sm shadow-emerald-50">
                                                        <CheckCircle2 size={12} className="mr-1.5" /> Success
                                                    </span>
                                                ) : (
                                                    <span className="inline-flex items-center px-2.5 py-1 rounded-full text-[10px] font-bold bg-rose-50 text-rose-700 border border-rose-100 shadow-sm shadow-rose-50">
                                                        <AlertCircle size={12} className="mr-1.5" /> Failed
                                                    </span>
                                                )}
                                            </td>
                                        </tr>
                                    ))
                                )}
                            </tbody>
                        </table>
                    </div>

                    {/* Loading Indicator */}
                    {loadingMore && (
                        <div className="p-8 flex justify-center items-center space-x-2 bg-zinc-50/30 border-t border-zinc-100">
                            <div className="w-1.5 h-1.5 bg-indigo-500 rounded-full animate-bounce [animation-delay:-0.3s]"></div>
                            <div className="w-1.5 h-1.5 bg-indigo-500 rounded-full animate-bounce [animation-delay:-0.15s]"></div>
                            <div className="w-1.5 h-1.5 bg-indigo-500 rounded-full animate-bounce"></div>
                            <span className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest ml-2">Loading more logs</span>
                        </div>
                    )}
                </div>
            </section>
        </div>
    );
}

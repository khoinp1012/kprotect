import { useState, useEffect, Fragment } from 'react';
import { Trash2, RefreshCw, Search, ShieldCheck, Clock, ChevronRight } from 'lucide-react';
import { api } from '../api';
import { useGlobal } from '../context/GlobalContext';
import { AuthorizedPattern } from '../types';
import { toast } from 'sonner';
import { ContextualUnlock } from './ContextualUnlock';

export function AuthorizedPatterns() {
    const { refreshAllowlist, isRootActive } = useGlobal();
    const [patterns, setPatterns] = useState<AuthorizedPattern[]>([]);
    const [loading, setLoading] = useState(true);
    const [searchTerm, setSearchTerm] = useState('');
    const [expandedIndex, setExpandedIndex] = useState<number | null>(null);

    const filteredPatterns = patterns.filter(p =>
        p.pattern.join('/').toLowerCase().includes(searchTerm.toLowerCase()) ||
        p.description.toLowerCase().includes(searchTerm.toLowerCase())
    );

    const loadPatterns = async () => {
        setLoading(true);
        try {
            const result = await api.getAllowlist();
            if (Array.isArray(result)) {
                setPatterns(result);
            }
        } catch (e: any) {
            // Silently fail - ContextualUnlock will guide user if root session needed
        } finally {
            setLoading(false);
        }
    };

    const handleRevoke = async (pattern: string[], matchMode: 'Exact' | 'Suffix') => {
        if (!isRootActive) {
            toast.error("Root session required to revoke patterns");
            return;
        }
        toast.promise(
            async () => {
                await api.revokePattern(pattern, matchMode);
                await loadPatterns();
                refreshAllowlist();
            },
            {
                loading: 'Revoking pattern...',
                success: 'Pattern revoked',
                error: (e) => `Revoke failed: ${e}`
            }
        );
    };

    useEffect(() => {
        loadPatterns();
    }, [isRootActive]);

    return (
        <div className="space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 px-1">
                <div className="flex items-center space-x-3">
                    <div className="p-2.5 bg-emerald-50 text-emerald-600 rounded-xl shadow-sm">
                        <ShieldCheck size={22} />
                    </div>
                    <div>
                        <h1 className="text-xl font-bold text-zinc-900 tracking-tight">Access Allowlist</h1>
                        <p className="text-sm text-zinc-500 font-medium">Authorized process lineages and matching rules.</p>
                    </div>
                </div>

                <div className="flex items-center space-x-2">
                    <div className="relative flex-1 sm:w-64">
                        <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-400" />
                        <input
                            type="text"
                            placeholder="Search patterns..."
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                            className="w-full pl-10 pr-4 py-2 text-sm border border-zinc-200 rounded-xl focus:outline-none focus:ring-4 focus:ring-indigo-500/10 focus:border-indigo-500 transition-all bg-white"
                        />
                    </div>
                    <button
                        onClick={loadPatterns}
                        className="p-2.5 text-zinc-500 hover:text-indigo-600 hover:bg-indigo-50 border border-zinc-200 rounded-xl transition-all active:scale-95"
                        title="Refresh list"
                    >
                        <RefreshCw size={18} className={`${loading ? 'animate-spin' : ''}`} />
                    </button>
                </div>
            </div>

            {!isRootActive && (
                <ContextualUnlock
                    description="Revoking authorized process patterns requires an active root session. Unlock to manage access allowlists."
                />
            )}

            <div className="bg-white border border-zinc-200 rounded-2xl overflow-hidden shadow-sm">
                {/* Mobile Card Layout */}
                < div className="md:hidden divide-y divide-zinc-100">
                    {loading ? (
                        <div className="p-12 text-center text-zinc-400 text-sm font-medium">Loading patterns...</div>
                    ) : filteredPatterns.length === 0 ? (
                        <div className="p-12 text-center text-zinc-400 text-sm font-medium italic">
                            No allowed patterns found matching your search.
                        </div>
                    ) : (
                        filteredPatterns.map((pattern, index) => (
                            <div key={index} className="p-5 active:bg-zinc-50 transition-colors">
                                <div className="flex justify-between items-start mb-4">
                                    <span className={`px-2 py-1 text-[10px] font-bold uppercase tracking-wider rounded-md ${pattern.match_mode === 'Suffix'
                                        ? 'bg-indigo-50 text-indigo-700 border border-indigo-100'
                                        : 'bg-emerald-50 text-emerald-700 border border-emerald-100'
                                        }`}>
                                        {pattern.match_mode} Mode
                                    </span>
                                    <button
                                        onClick={() => handleRevoke(pattern.pattern, pattern.match_mode)}
                                        disabled={!isRootActive}
                                        className="p-2 text-rose-600 hover:bg-rose-50 rounded-lg border border-rose-100 transition-all active:scale-95 disabled:opacity-50 disabled:cursor-not-allowed"
                                    >
                                        <Trash2 size={16} />
                                    </button>
                                </div>
                                <div className="space-y-4">
                                    <div className="flex flex-col space-y-1.5">
                                        <p className="text-[10px] font-bold text-zinc-400 uppercase tracking-widest">Process Lineage</p>
                                        <div className="flex flex-wrap items-center gap-1.5 p-3 bg-zinc-50 rounded-xl border border-zinc-100">
                                            {pattern.pattern.map((proc, i) => (
                                                <div key={i} className="flex items-center">
                                                    <span className="font-mono text-[10px] bg-white px-2 py-0.5 rounded border border-zinc-200 text-zinc-700 break-all">
                                                        {proc}
                                                    </span>
                                                    {i < pattern.pattern.length - 1 && (
                                                        <ChevronRight size={10} className="mx-0.5 text-zinc-300 shrink-0" />
                                                    )}
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                    <div>
                                        <p className="text-[10px] font-bold text-zinc-400 uppercase tracking-widest mb-1">Description</p>
                                        <p className="text-sm font-medium text-zinc-700">{pattern.description || 'No description provided'}</p>
                                    </div>
                                    <div className="flex items-center text-[10px] text-zinc-400 font-medium">
                                        <Clock size={10} className="mr-1.5" />
                                        {new Date(pattern.authorized_at * 1000).toLocaleString()}
                                    </div>
                                </div>
                            </div>
                        ))
                    )}
                </div>

                {/* Desktop Table Layout */}
                <div className="hidden md:block overflow-x-auto">
                    <table className="min-w-full divide-y divide-zinc-100">
                        <thead className="bg-zinc-50">
                            <tr>
                                <th className="px-6 py-4 text-left text-[11px] font-bold text-zinc-500 uppercase tracking-widest">Pattern Chain</th>
                                <th className="px-6 py-4 text-left text-[11px] font-bold text-zinc-500 uppercase tracking-widest">Match Mode</th>
                                <th className="px-6 py-4 text-left text-[11px] font-bold text-zinc-500 uppercase tracking-widest">Context / Note</th>
                                <th className="px-6 py-4 text-left text-[11px] font-bold text-zinc-500 uppercase tracking-widest">Authorized At</th>
                                <th className="px-6 py-4 text-right text-[11px] font-bold text-zinc-500 uppercase tracking-widest">Actions</th>
                            </tr>
                        </thead>
                        <tbody className="bg-white divide-y divide-zinc-100">
                            {loading ? (
                                <tr>
                                    <td colSpan={5} className="px-6 py-16 text-center text-zinc-400 text-sm font-medium animate-pulse">
                                        Fetching authorized lineage rules...
                                    </td>
                                </tr>
                            ) : filteredPatterns.length === 0 ? (
                                <tr>
                                    <td colSpan={5} className="px-6 py-16 text-center text-zinc-400 text-sm italic">
                                        No allowed patterns found matching your search.
                                    </td>
                                </tr>
                            ) : (
                                filteredPatterns.map((pattern, index) => (
                                    <Fragment key={index}>
                                        <tr
                                            onClick={() => setExpandedIndex(expandedIndex === index ? null : index)}
                                            className={`hover:bg-zinc-50/50 transition-colors group cursor-pointer ${expandedIndex === index ? 'bg-indigo-50/30' : ''}`}
                                        >
                                            <td className="px-6 py-4 max-w-sm">
                                                <div className="flex flex-wrap items-center gap-1.5">
                                                    {pattern.pattern.map((proc, i) => (
                                                        <div key={i} className="flex items-center">
                                                            <span className="font-mono text-[10px] bg-zinc-100 group-hover:bg-white px-2 py-0.5 rounded border border-zinc-200 text-zinc-600 transition-colors" title={proc}>
                                                                {proc.split('/').pop() || proc}
                                                            </span>
                                                            {i < pattern.pattern.length - 1 && (
                                                                <ChevronRight size={10} className="mx-0.5 text-zinc-300" />
                                                            )}
                                                        </div>
                                                    ))}
                                                </div>
                                            </td>
                                            <td className="px-6 py-4 whitespace-nowrap">
                                                <span className={`px-2.5 py-1 text-[10px] font-bold rounded-lg border ${pattern.match_mode === 'Suffix'
                                                    ? 'bg-indigo-50 text-indigo-700 border-indigo-100'
                                                    : 'bg-emerald-50 text-emerald-700 border-emerald-100'
                                                    }`}>
                                                    {pattern.match_mode}
                                                </span>
                                            </td>
                                            <td className="px-6 py-4 text-sm text-zinc-600 font-medium max-w-[200px] truncate">
                                                {pattern.description}
                                            </td>
                                            <td className="px-6 py-4 whitespace-nowrap text-[11px] text-zinc-400 font-mono">
                                                {new Date(pattern.authorized_at * 1000).toLocaleString([], {
                                                    month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit'
                                                })}
                                            </td>
                                            <td className="px-6 py-4 whitespace-nowrap text-right" onClick={(e) => e.stopPropagation()}>
                                                <button
                                                    onClick={() => handleRevoke(pattern.pattern, pattern.match_mode)}
                                                    disabled={!isRootActive}
                                                    className="p-2 text-rose-500 hover:text-rose-700 hover:bg-rose-50 border border-transparent hover:border-rose-100 rounded-xl transition-all active:scale-95 disabled:opacity-50 disabled:cursor-not-allowed"
                                                    title={isRootActive ? "Revoke Authorization" : "Root session required"}
                                                >
                                                    <Trash2 size={16} />
                                                </button>
                                            </td>
                                        </tr>
                                        {expandedIndex === index && (
                                            <tr className="bg-indigo-50/20 animate-in fade-in slide-in-from-top-1">
                                                <td colSpan={5} className="px-8 py-6 border-t border-zinc-100">
                                                    <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
                                                        <div className="md:col-span-2 space-y-4">
                                                            <div>
                                                                <h4 className="text-[10px] font-bold text-zinc-400 uppercase tracking-widest mb-3">Full Process Ancestry</h4>
                                                                <div className="space-y-2 bg-white/50 p-4 rounded-xl border border-zinc-200/50 shadow-inner">
                                                                    {pattern.pattern.map((proc, i) => (
                                                                        <div key={i} className="flex items-center space-x-3">
                                                                            <span className="text-[10px] font-bold text-zinc-300 w-4">{i + 1}.</span>
                                                                            <span className="font-mono text-[11px] text-zinc-700 break-all">{proc}</span>
                                                                        </div>
                                                                    ))}
                                                                </div>
                                                            </div>
                                                        </div>
                                                        <div className="space-y-6">
                                                            <div>
                                                                <h4 className="text-[10px] font-bold text-zinc-400 uppercase tracking-widest mb-2">Rule Definition</h4>
                                                                <div className="bg-white p-4 rounded-xl border border-zinc-100 shadow-sm space-y-3">
                                                                    <div>
                                                                        <p className="text-[10px] text-zinc-400 font-bold uppercase tracking-tight">Status</p>
                                                                        <div className="flex items-center mt-1 space-x-2">
                                                                            <div className="w-2 h-2 rounded-full bg-emerald-500"></div>
                                                                            <span className="text-sm font-bold text-zinc-900">Active Policy</span>
                                                                        </div>
                                                                    </div>
                                                                    <div>
                                                                        <p className="text-[10px] text-zinc-400 font-bold uppercase tracking-tight">Context</p>
                                                                        <p className="text-sm font-medium text-zinc-700 mt-0.5">{pattern.description}</p>
                                                                    </div>
                                                                    <div className="pt-2 border-t border-zinc-50">
                                                                        <p className="text-[10px] text-zinc-400 font-bold uppercase tracking-tight flex items-center">
                                                                            <Clock size={10} className="mr-1" /> Authorized On
                                                                        </p>
                                                                        <p className="text-xs font-mono text-zinc-600 mt-0.5">
                                                                            {new Date(pattern.authorized_at * 1000).toLocaleString()}
                                                                        </p>
                                                                    </div>
                                                                </div>
                                                            </div>
                                                        </div>
                                                    </div>
                                                </td>
                                            </tr>
                                        )}
                                    </Fragment>
                                ))
                            )}
                        </tbody>
                    </table>
                </div>
            </div >

            <div className="flex items-center justify-between px-2 text-[11px] font-bold text-zinc-400 uppercase tracking-widest">
                <span>Active Policies</span>
                <span>{filteredPatterns.length} Rules Defined</span>
            </div>
        </div >
    );
}



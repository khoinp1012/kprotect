import React, { useState, useRef, useCallback, Fragment, useMemo } from 'react';
import { Check, X, Trash2, Activity, CheckCircle, FileText, Search, ChevronRight, Hash, Clock, ShieldCheck, Layers } from 'lucide-react';
import { api } from '../api';
import { toast } from 'sonner';
import { Event, AuthorizedPattern } from '../types';
import { useGlobal } from '../context/GlobalContext';

export function EventList() {
    const { events, clearEvents, refreshAllowlist, loadMoreEvents, compressionEnabled, setCompressionEnabled, allowlist } = useGlobal();
    const [selectedEventId, setSelectedEventId] = useState<number | string | null>(null);

    // Filter Logic
    const [searchTerm, setSearchTerm] = useState('');
    const [loadingMore, setLoadingMore] = useState(false);
    const [visibleCount, setVisibleCount] = useState(50);

    // Authorization Modal State
    const [authModalOpen, setAuthModalOpen] = useState(false);
    const [selectedEvent, setSelectedEvent] = useState<Event | null>(null);
    const [authMode, setAuthMode] = useState<'Suffix' | 'Exact'>('Suffix');
    const [authDesc, setAuthDesc] = useState('');

    // Revoke Modal State
    const [revokeModalOpen, setRevokeModalOpen] = useState(false);
    const [revokeCandidates, setRevokeCandidates] = useState<{ rule: AuthorizedPattern, matchType: string }[]>([]);
    const filteredEvents = useMemo(() => {
        const term = searchTerm.toLowerCase();
        return events.filter(e =>
            e.path.toLowerCase().includes(term) ||
            e.status.toLowerCase().includes(term) ||
            e.pid.toString().includes(term)
        );
    }, [events, searchTerm]);

    const displayedEvents = useMemo(() => {
        return filteredEvents.slice(0, visibleCount);
    }, [filteredEvents, visibleCount]);

    // Infinite Scroll Intersection Observer
    const observer = useRef<IntersectionObserver | null>(null);
    const lastElementRef = useCallback((node: HTMLDivElement | HTMLTableRowElement | null) => {
        if (loadingMore) return;
        if (observer.current) observer.current.disconnect();

        observer.current = new IntersectionObserver(entries => {
            if (entries[0].isIntersecting) {
                // If we have more local filtered events to show, just show them
                if (visibleCount < filteredEvents.length) {
                    setVisibleCount(prev => prev + 50);
                }
                // If we ran out of filtered events, fetch more from backend
                else {
                    setLoadingMore(true);
                    loadMoreEvents().finally(() => setLoadingMore(false));
                }
            }
        });

        if (node) observer.current.observe(node);
    }, [loadingMore, loadMoreEvents, events.length, visibleCount, filteredEvents.length]);

    const openAuthModal = (event: Event) => {
        setSelectedEvent(event);
        // Use 'Exact' for complete chains (from systemd(1)), 'Suffix' for partial chains
        setAuthMode(event.complete ? 'Exact' : 'Suffix');
        // Clearer description: "Authorize all file access via [basename]"
        const basename = event.path.split('/').pop() || event.path;
        setAuthDesc(`Authorize all file access via ${basename}`);
        setAuthModalOpen(true);
    };

    const closeAuthModal = () => {
        setAuthModalOpen(false);
        setSelectedEvent(null);
    };

    const submitAuthorize = async () => {
        if (!selectedEvent) return;

        try {
            const exists = allowlist.some(p =>
                p.pattern.length === selectedEvent.chain.length &&
                p.pattern.every((val: string, i: number) => val === selectedEvent.chain[i])
            );

            if (exists) {
                toast.error("This pattern chain is already authorized.");
                return;
            }
        } catch (e) {
            console.error("Failed to check duplicates", e);
        }

        toast.promise(
            async () => {
                await api.authorizePattern(
                    selectedEvent.chain,
                    authMode,
                    authDesc
                );
                refreshAllowlist();
            },
            {
                loading: 'Authorizing...',
                success: 'Authorized successfully',
                error: (e) => `Auth failed: ${e}`
            }
        );
        closeAuthModal();
    };

    const handleRevoke = async (event: Event) => {
        try {
            const candidates: { rule: AuthorizedPattern, matchType: string }[] = [];
            const eventChainStr = JSON.stringify(event.chain);

            allowlist.forEach((p) => {
                if (JSON.stringify(p.pattern) === eventChainStr) {
                    candidates.push({ rule: p, matchType: 'Exact Match' });
                }
                else if (p.match_mode === 'Suffix' && event.chain.length >= p.pattern.length) {
                    const suffix = event.chain.slice(event.chain.length - p.pattern.length);
                    if (JSON.stringify(suffix) === JSON.stringify(p.pattern)) {
                        candidates.push({ rule: p, matchType: 'Suffix Match' });
                    }
                }
            });

            if (candidates.length === 0) {
                toast.error("No matching authorization rule found for this event.");
                return;
            }

            candidates.sort((a, b) => b.rule.pattern.length - a.rule.pattern.length);
            setRevokeCandidates(candidates);
            setRevokeModalOpen(true);
        } catch (e) {
            toast.error("Failed to check allowlist: " + e);
        }
    };

    const confirmRevoke = async (rule: AuthorizedPattern) => {
        toast.promise(
            async () => {
                await api.revokePattern(rule.pattern, rule.match_mode);
                refreshAllowlist();
                setRevokeModalOpen(false);
            },
            {
                loading: 'Revoking...',
                success: 'Revoked successfully',
                error: (e) => `Revoke failed: ${e}`
            }
        );
    };

    return (
        <div className="bg-white border border-zinc-200 rounded-xl overflow-hidden shadow-sm">
            {/* Toolbar */}
            <div className="px-5 py-4 border-b border-zinc-200 flex flex-col sm:flex-row justify-between items-start sm:items-center bg-white space-y-3 sm:space-y-0">
                <div className="flex items-center space-x-3">
                    <div className="p-2 bg-indigo-50 rounded-lg">
                        <Activity size={18} className="text-indigo-600" />
                    </div>
                    <div>
                        <h3 className="text-sm font-bold text-zinc-900 leading-none">Security Access Logs</h3>
                        <p className="text-[10px] text-zinc-500 mt-1 uppercase tracking-wider font-semibold">Live Feed</p>
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
                    <button
                        type="button"
                        onClick={() => {
                            console.log('[CompressionToggle] Button clicked!');
                            console.log('[CompressionToggle] Current state:', compressionEnabled);
                            console.log('[CompressionToggle] Setting to:', !compressionEnabled);
                            setCompressionEnabled(!compressionEnabled);
                            console.log('[CompressionToggle] setCompressionEnabled called');
                        }}
                        className={`flex items-center px-3 py-1.5 rounded-lg text-xs font-bold transition-all border ${compressionEnabled
                            ? 'text-indigo-600 bg-indigo-50 border-indigo-200 hover:bg-indigo-100'
                            : 'text-zinc-500 bg-zinc-50 border-zinc-200 hover:bg-zinc-100'
                            }`}
                        title={compressionEnabled ? "Disable compression" : "Enable compression"}
                    >
                        <Layers size={14} className="sm:mr-2" />
                        <span className="hidden sm:inline">
                            {compressionEnabled ? 'Compressed' : 'Raw Feed'}
                        </span>
                    </button>
                    <button
                        type="button"
                        onClick={clearEvents}
                        className="flex items-center px-3 py-1.5 rounded-lg text-xs font-bold text-rose-600 bg-rose-50 hover:bg-rose-100 border border-rose-200 transition-all"
                    >
                        <Trash2 size={14} className="sm:mr-2" />
                        <span className="hidden sm:inline">Clear</span>
                    </button>
                </div>
            </div>

            {/* Mobile View */}
            <div className="md:hidden divide-y divide-zinc-100">
                {displayedEvents.map((event, idx) => (
                    <MobileEventCard
                        key={event.id}
                        event={event}
                        isLast={idx === displayedEvents.length - 1}
                        lastElementRef={lastElementRef}
                        isSelected={selectedEventId === event.id}
                        onSelect={() => setSelectedEventId(prev => prev === event.id ? null : event.id)}
                        onAuthorize={() => openAuthModal(event)}
                        onRevoke={() => handleRevoke(event)}
                        allowlist={allowlist}
                    />
                ))}
            </div>

            {/* Desktop View */}
            <div className="hidden md:block overflow-x-auto">
                <table className="w-full text-left text-sm text-zinc-600">
                    <thead className="bg-zinc-50 text-zinc-500 uppercase text-[11px] font-semibold tracking-wider border-b border-zinc-200">
                        <tr>
                            <th className="px-6 py-3">Event</th>
                            <th className="px-6 py-3">Status</th>
                            <th className="px-6 py-3">PID</th>
                            <th className="px-6 py-3">Target Resource</th>
                            <th className="px-6 py-3">Process Chain</th>
                            <th className="px-6 py-3 text-right sticky right-0 bg-zinc-50 z-10">Actions</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-zinc-100">
                        {displayedEvents.map((event, idx) => (
                            <EventRow
                                key={event.id}
                                event={event}
                                isLast={idx === displayedEvents.length - 1}
                                lastElementRef={lastElementRef}
                                isSelected={selectedEventId === event.id}
                                onSelect={() => setSelectedEventId(prev => prev === event.id ? null : event.id)}
                                onAuthorize={() => openAuthModal(event)}
                                onRevoke={() => handleRevoke(event)}
                                allowlist={allowlist}
                            />
                        ))}
                    </tbody>
                </table>
            </div>

            {/* Loading Indicator */}
            {loadingMore && (
                <div className="p-8 flex justify-center items-center space-x-2 bg-zinc-50/50 border-t border-zinc-100">
                    <div className="w-1.5 h-1.5 bg-indigo-500 rounded-full animate-bounce [animation-delay:-0.3s]"></div>
                    <div className="w-1.5 h-1.5 bg-indigo-500 rounded-full animate-bounce [animation-delay:-0.15s]"></div>
                    <div className="w-1.5 h-1.5 bg-indigo-500 rounded-full animate-bounce"></div>
                    <span className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest ml-2">Loading More History</span>
                </div>
            )}

            {filteredEvents.length === 0 && !loadingMore && (
                <div className="p-20 text-center">
                    <Activity size={32} className="mx-auto text-zinc-200 mb-4" />
                    <p className="text-zinc-500 text-sm font-medium">No activity found matching your filters</p>
                </div>
            )}

            {/* Auth Modal */}
            {authModalOpen && selectedEvent && (
                <div className="fixed inset-0 bg-zinc-900/60 backdrop-blur-sm flex items-end sm:items-center justify-center z-50 p-0 sm:p-4">
                    <div className="bg-white rounded-t-2xl sm:rounded-2xl shadow-2xl w-full max-w-lg p-6 animate-in slide-in-from-bottom-full sm:slide-in-from-bottom-4 duration-300">
                        <div className="flex justify-between items-center mb-6">
                            <h3 className={`text-lg font-bold ${!selectedEvent.complete ? 'text-amber-600' : 'text-zinc-900'}`}>
                                {!selectedEvent.complete ? 'Authorize Partial Chain' : 'Authorize Pattern'}
                            </h3>
                            <button onClick={closeAuthModal} className="p-2 hover:bg-zinc-100 rounded-full transition-colors">
                                <X size={20} className="text-zinc-400" />
                            </button>
                        </div>

                        <div className="space-y-6">
                            <div>
                                <label className="block text-xs font-bold text-zinc-400 uppercase tracking-wider mb-2">Pattern Chain</label>
                                <div className="bg-zinc-50 p-4 rounded-xl text-[11px] font-mono text-zinc-600 border border-zinc-200 max-h-40 overflow-y-auto">
                                    {selectedEvent.chain.map((c, i) => (
                                        <div key={i} className="flex items-center space-x-2 py-0.5">
                                            <span className="text-zinc-300">↳</span>
                                            <span>{c}</span>
                                        </div>
                                    ))}
                                </div>
                                {!selectedEvent.complete && (
                                    <p className="mt-3 text-[11px] text-amber-700 bg-amber-50 p-3 rounded-lg border border-amber-200/50 leading-relaxed font-medium">
                                        ⚠️ You are authorizing an incomplete process tree. This will allow any sequence that ends with these processes.
                                    </p>
                                )}
                                <div className="mt-4 p-3 bg-indigo-50/50 border border-indigo-100 rounded-xl">
                                    <div className="flex items-start space-x-2.5">
                                        <ShieldCheck size={16} className="text-indigo-600 mt-0.5 shrink-0" />
                                        <div>
                                            <p className="text-[11px] font-bold text-indigo-900 uppercase tracking-tight">Security Scope</p>
                                            <p className="text-[11px] text-indigo-700/80 leading-relaxed font-medium mt-0.5">
                                                This grants the process lineage access to <strong>all protected files</strong> and sensitive zones.
                                            </p>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            <div className="space-y-4">
                                <div>
                                    <label className="block text-xs font-bold text-zinc-400 uppercase tracking-wider mb-2">Description</label>
                                    <input
                                        type="text"
                                        value={authDesc}
                                        onChange={(e) => setAuthDesc(e.target.value)}
                                        className="w-full px-4 py-3 rounded-xl border border-zinc-300 focus:outline-none focus:ring-4 focus:ring-indigo-500/10 focus:border-indigo-500 text-sm transition-all"
                                        placeholder="Add a context for this rule..."
                                    />
                                </div>
                                <div className="flex flex-col sm:flex-row space-y-2 sm:space-y-0 sm:space-x-3">
                                    <button
                                        onClick={closeAuthModal}
                                        className="flex-1 px-4 py-3 text-sm font-bold text-zinc-600 bg-zinc-100 hover:bg-zinc-200 rounded-xl transition-all"
                                    >
                                        Cancel
                                    </button>
                                    <button
                                        onClick={submitAuthorize}
                                        className={`flex-[2] px-4 py-3 text-sm font-bold text-white rounded-xl shadow-lg shadow-indigo-200 transition-all ${!selectedEvent.complete ? 'bg-amber-600 hover:bg-amber-700 shadow-amber-100' : 'bg-indigo-600 hover:bg-indigo-700'}`}
                                    >
                                        Confirm Authorization
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {/* Revoke Modal */}
            {revokeModalOpen && (
                <div className="fixed inset-0 bg-zinc-900/60 backdrop-blur-sm flex items-end sm:items-center justify-center z-50 p-0 sm:p-4">
                    <div className="bg-white rounded-t-2xl sm:rounded-2xl shadow-2xl w-full max-w-lg p-6 animate-in slide-in-from-bottom-full sm:slide-in-from-bottom-4 duration-300">
                        <div className="flex items-center justify-between mb-6">
                            <div className="flex items-center space-x-3">
                                <div className="p-2 bg-rose-50 rounded-lg">
                                    <Trash2 size={20} className="text-rose-600" />
                                </div>
                                <h3 className="text-lg font-bold text-zinc-900">Revoke Rule</h3>
                            </div>
                            <button onClick={() => setRevokeModalOpen(false)} className="p-2 hover:bg-zinc-100 rounded-full transition-colors">
                                <X size={20} className="text-zinc-400" />
                            </button>
                        </div>

                        <div className="space-y-4 mb-8 max-h-96 overflow-y-auto">
                            {revokeCandidates.map((cand, idx) => (
                                <div key={idx} className="border border-zinc-100 rounded-xl p-4 bg-zinc-50 hover:bg-white hover:border-rose-200 hover:shadow-md transition-all group">
                                    <div className="flex justify-between items-center mb-3">
                                        <span className={`text-[10px] uppercase font-bold px-2 py-1 rounded-md ${cand.matchType === 'Exact Match' ? 'bg-indigo-100 text-indigo-700' : 'bg-amber-100 text-amber-700'} `}>
                                            {cand.matchType}
                                        </span>
                                        <button
                                            onClick={() => confirmRevoke(cand.rule)}
                                            className="text-[11px] font-bold text-white bg-rose-600 hover:bg-rose-700 px-4 py-2 rounded-lg shadow-sm active:scale-95 transition-all"
                                        >
                                            Revoke Now
                                        </button>
                                    </div>
                                    <div className="font-mono text-[10px] text-zinc-500 bg-white p-3 rounded-lg border border-zinc-200/50 break-all leading-relaxed">
                                        {cand.rule.pattern.join(" \n↳ ")}
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}

const MobileEventCard = React.memo(({ event, isLast, lastElementRef, isSelected, onSelect, onAuthorize, onRevoke, allowlist }: any) => {
    const isNowAuthorized = useMemo(() => {
        return allowlist.some((p: AuthorizedPattern) => {
            if (p.match_mode === 'Exact') {
                return JSON.stringify(p.pattern) === JSON.stringify(event.chain);
            } else {
                if (event.chain.length < p.pattern.length) return false;
                const suffix = event.chain.slice(event.chain.length - p.pattern.length);
                return JSON.stringify(suffix) === JSON.stringify(p.pattern);
            }
        });
    }, [event.chain, allowlist]);

    return (
        <div
            ref={isLast ? lastElementRef : null}
            onClick={onSelect}
            className={`p-4 transition-colors ${isSelected ? 'bg-indigo-50/10' : 'active:bg-zinc-50'}`}
        >
            <div className="flex justify-between items-start mb-3">
                <div className="flex items-center space-x-2">
                    <span className="font-mono text-[10px] text-zinc-400">#{event.id}</span>
                    {event.count && event.count > 1 && (
                        <span className="px-1.5 py-0.5 bg-zinc-200 text-zinc-700 rounded text-[9px] font-bold">
                            {event.count}x
                        </span>
                    )}
                    <StatusBadge status={event.status} isAuthorized={isNowAuthorized} />
                </div>
                <div className="flex items-center space-x-1.5">
                    {event.status !== 'Birth' && event.chain && event.chain.length > 0 && (
                        <>
                            {isNowAuthorized ? (
                                <button
                                    onClick={(e) => { e.stopPropagation(); onRevoke(); }}
                                    className="p-1.5 rounded-md bg-rose-50 text-rose-600 border border-rose-100 hover:bg-rose-100 transition-all"
                                    title="Revoke/Undo"
                                >
                                    <X size={14} strokeWidth={2.5} />
                                </button>
                            ) : (
                                <button
                                    onClick={(e) => { e.stopPropagation(); onAuthorize(); }}
                                    className={`p-1.5 rounded-md border transition-all ${event.complete
                                        ? 'bg-emerald-50 text-emerald-600 border-emerald-100 hover:bg-emerald-100'
                                        : 'bg-amber-50 text-amber-600 border-amber-100 hover:bg-emerald-100'}`}
                                    title={event.complete ? "Authorize Pattern" : "Authorize Partial Chain"}
                                >
                                    <Check size={14} strokeWidth={2.5} />
                                </button>
                            )}
                        </>
                    )}
                </div>
            </div>

            <div className="space-y-2">
                <div className="flex items-center text-xs text-zinc-600 space-x-2">
                    <FileText size={12} className="text-zinc-400" />
                    <span className="font-mono text-zinc-700 break-all">{event.path}</span>
                </div>
                <div className="flex items-center text-[10px] text-zinc-500 space-x-4">
                    <div className="flex items-center">
                        <Hash size={10} className="mr-1" /> PID: {event.pid}
                    </div>
                    <div className="flex items-center">
                        <Clock size={10} className="mr-1" /> {new Date(event.timestamp).toLocaleString([], {
                            year: 'numeric', month: 'short', day: '2-digit',
                            hour: '2-digit', minute: '2-digit', hour12: false
                        })}
                    </div>
                </div>
            </div>

            {isSelected && (
                <div className="mt-4 p-3 bg-zinc-50 rounded-lg border border-zinc-200 animate-in fade-in slide-in-from-top-1">
                    <p className="text-[10px] font-bold text-zinc-400 uppercase tracking-tight mb-2">Process Chain</p>
                    <div className="space-y-1.5">
                        {event.chain.map((proc: string, i: number) => (
                            <div key={i} className="flex items-center text-[11px] font-mono text-zinc-600">
                                {i < event.chain.length - 1 ? (
                                    <div className="w-1.5 h-1.5 rounded-full bg-zinc-300 mr-2 shrink-0" />
                                ) : (
                                    <div className="w-1.5 h-1.5 rounded-full bg-indigo-500 mr-2 shrink-0" />
                                )}
                                <span className="break-all">{proc}</span>
                            </div>
                        ))}
                    </div>
                </div>
            )}
        </div>
    );
});

const EventRow = React.memo(({ event, isLast, lastElementRef, isSelected, onSelect, onAuthorize, onRevoke, allowlist }: any) => {
    const isNowAuthorized = useMemo(() => {
        return allowlist.some((p: AuthorizedPattern) => {
            if (p.match_mode === 'Exact') {
                return JSON.stringify(p.pattern) === JSON.stringify(event.chain);
            } else {
                if (event.chain.length < p.pattern.length) return false;
                const suffix = event.chain.slice(event.chain.length - p.pattern.length);
                return JSON.stringify(suffix) === JSON.stringify(p.pattern);
            }
        });
    }, [event.chain, allowlist]);

    return (
        <Fragment>
            <tr
                ref={isLast ? lastElementRef : null}
                onClick={onSelect}
                className={`transition-colors group cursor-pointer ${isSelected ? 'bg-indigo-50/50' : 'hover:bg-zinc-50/80'}`}
            >
                <td className="px-6 py-4 font-mono text-zinc-400 text-[10px] w-28 align-top">
                    <div className="flex items-center gap-2">
                        <span>#{event.id}</span>
                        {event.count && event.count > 1 && (
                            <span className="px-1.5 py-0.5 bg-zinc-200 text-zinc-700 rounded text-[9px] font-bold">
                                {event.count}x
                            </span>
                        )}
                    </div>
                    <div className="text-[10px] text-zinc-500 mt-1">
                        {new Date(event.timestamp).toLocaleString([], {
                            year: 'numeric', month: 'numeric', day: 'numeric',
                            hour: '2-digit', minute: '2-digit', second: '2-digit',
                            hour12: false
                        })}
                    </div>
                </td>
                <td className="px-6 py-4 align-top w-32">
                    <StatusBadge status={event.status} isAuthorized={isNowAuthorized} />
                </td>
                <td className="px-6 py-4 font-mono text-zinc-500 text-xs align-top w-20">{event.pid}</td>
                <td className="px-6 py-4 align-top max-w-[200px]">
                    <div className="flex items-center space-x-2">
                        <FileText size={14} className="text-zinc-400 shrink-0" />
                        <span className="font-mono text-[11px] text-zinc-700 break-all bg-zinc-50/50 px-1.5 py-0.5 rounded border border-zinc-100">
                            {event.path}
                        </span>
                    </div>
                </td>
                <td className="px-6 py-4 align-top">
                    <div className="flex flex-wrap items-center gap-1.5">
                        {event.chain && event.chain.length > 0 ? (
                            event.chain.map((proc: string, pIdx: number) => {
                                const parts = proc.split(' ');
                                const pathPart = parts[0];
                                const basename = pathPart.split('/').pop() || pathPart;

                                return (
                                    <div key={pIdx} className="flex items-center">
                                        <span
                                            className={`font-mono text-[10px] px-1.5 py-0.5 rounded border ${pIdx === event.chain.length - 1
                                                ? 'bg-zinc-100 text-zinc-900 border-zinc-300 font-bold'
                                                : 'bg-zinc-50 text-zinc-500 border-zinc-200'
                                                }`}
                                            title={proc}
                                        >
                                            {basename}
                                        </span>
                                        {pIdx < event.chain.length - 1 && (
                                            <ChevronRight size={10} className="text-zinc-300 mx-0.5" />
                                        )}
                                    </div>
                                );
                            })
                        ) : (
                            <span className="text-zinc-400 italic text-xs">No chain</span>
                        )}
                    </div>
                </td>
                <td className="px-6 py-4 text-right space-x-1.5 align-top w-40 sticky right-0 bg-white group-hover:bg-zinc-50/80 transition-colors z-10" onClick={(e) => e.stopPropagation()}>
                    {event.status !== 'Birth' && event.chain && event.chain.length > 0 && (
                        <div className="flex items-center justify-end space-x-1.5">
                            {isNowAuthorized ? (
                                <button
                                    type="button"
                                    onClick={onRevoke}
                                    className="text-rose-600 hover:text-rose-700 bg-rose-50 border border-rose-100 p-1.5 rounded-lg transition-all hover:bg-rose-100"
                                    title="Revoke/Undo"
                                >
                                    <X size={14} strokeWidth={2.5} />
                                </button>
                            ) : (
                                <button
                                    type="button"
                                    onClick={onAuthorize}
                                    className={`p-1.5 rounded-lg border transition-all ${event.complete
                                        ? 'text-emerald-600 hover:text-emerald-700 bg-emerald-50 border-emerald-100 hover:bg-emerald-100'
                                        : 'text-amber-600 hover:text-amber-700 bg-amber-50 border-amber-100 hover:bg-amber-100'}`}
                                    title={event.complete ? "Authorize" : "Authorize Partial"}
                                >
                                    <Check size={14} strokeWidth={2.5} />
                                </button>
                            )}
                        </div>
                    )}
                </td>
            </tr>
            {isSelected && (
                <tr className="bg-zinc-50/50">
                    <td colSpan={6} className="px-6 py-4 border-t border-zinc-100">
                        <div className="bg-white p-4 rounded-xl border border-zinc-200 shadow-sm">
                            <h4 className="text-[10px] font-bold text-zinc-400 uppercase tracking-wider mb-3">Full Process Chain Detail</h4>
                            <div className="flex flex-wrap items-center gap-2 p-3 bg-zinc-50/50 rounded-lg border border-zinc-100">
                                {event.chain.map((proc: string, i: number) => (
                                    <div key={i} className="flex items-center">
                                        <div className={`px-2 py-1 rounded-md text-[11px] font-mono border ${i === event.chain.length - 1
                                            ? 'bg-indigo-50 border-indigo-200 text-indigo-900 font-bold'
                                            : 'bg-white border-zinc-200 text-zinc-600'
                                            }`}>
                                            {proc}
                                        </div>
                                        {i < event.chain.length - 1 && (
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
    );
});

function StatusBadge({ status, isAuthorized }: { status: string, isAuthorized?: boolean }) {
    if (isAuthorized || status === 'Verified') {
        return (
            <span className="inline-flex items-center space-x-1.5 text-emerald-600 bg-emerald-50 px-2 py-0.5 rounded-full border border-emerald-100">
                <CheckCircle size={10} strokeWidth={3} />
                <span className="text-[10px] font-bold">Authorized</span>
            </span>
        );
    }
    if (status === 'Blocked') {
        return (
            <span className="inline-flex items-center space-x-1.5 text-rose-600 bg-rose-50 px-2 py-0.5 rounded-full border border-rose-100" title="Originally Blocked">
                <div className="w-1.5 h-1.5 rounded-full bg-rose-500"></div>
                <span className="text-[10px] font-bold">Blocked</span>
            </span>
        );
    }
    if (status === 'Unknown') {
        return (
            <span className="inline-flex items-center space-x-1.5 text-amber-600 bg-amber-50 px-2 py-0.5 rounded-full border border-amber-100">
                <div className="w-1.5 h-1.5 rounded-full bg-amber-500"></div>
                <span className="text-[10px] font-bold">Unknown</span>
            </span>
        );
    }
    if (status === 'Birth') {
        return (
            <span className="inline-flex items-center space-x-1.5 text-blue-600 bg-blue-50 px-2 py-0.5 rounded-full border border-blue-100">
                <div className="w-1.5 h-1.5 rounded-full bg-blue-500"></div>
                <span className="text-[10px] font-bold">Birth</span>
            </span>
        );
    }
    return null;
}

import { useState, useEffect } from 'react';
import { ShieldAlert, Plus, Trash2, Code2, FolderLock, Terminal, History } from 'lucide-react';
import { ZonesConfig } from '../types';
import { api } from '../api';
import { toast } from 'sonner';
import { useGlobal } from '../context/GlobalContext';
import { homeDir } from '@tauri-apps/api/path';

import { ContextualUnlock } from '../components/ContextualUnlock';

interface EnrichmentConfig {
    enrichment_patterns: string[];
}

import { SystemStats } from '../api';

const UsageBadge = ({ current, max, label }: { current: number, max: number, label: string }) => {
    const isClose = current / max > 0.8;
    return (
        <div className="flex items-center space-x-2 bg-white border border-zinc-200 px-2.5 py-1 rounded-lg shadow-sm">
            <span className="text-[10px] font-bold text-zinc-400 uppercase tracking-tight">{label}</span>
            <span className={`text-xs font-mono font-bold ${isClose ? 'text-rose-500' : 'text-zinc-600'}`}>
                {current}/{max}
            </span>
        </div>
    );
};

interface PolicyProps {
    initialTab?: 'zones' | 'enrichment';
}

export function Policies({ initialTab = 'zones' }: PolicyProps) {
    const { isRootActive } = useGlobal();
    const [activeTab, setActiveTab] = useState<'zones' | 'enrichment'>(initialTab);

    // Sync with prop when it changes
    useEffect(() => {
        setActiveTab(initialTab);
    }, [initialTab]);

    const [zones, setZones] = useState<ZonesConfig>({ red_zones: [], green_zones: [] });
    const [enrichment, setEnrichment] = useState<EnrichmentConfig>({ enrichment_patterns: [] });
    const [usage, setUsage] = useState<SystemStats | null>(null);

    const [newRed, setNewRed] = useState('');
    const [newPattern, setNewPattern] = useState('');
    const [homePath, setHomePath] = useState('');

    useEffect(() => {
        homeDir().then(setHomePath).catch(console.error);
    }, []);

    useEffect(() => {
        fetchData();
    }, [isRootActive]);

    async function fetchData() {
        try {
            const [z, e] = await Promise.all([
                api.getZones(),
                api.getEnrichmentPatterns()
            ]);
            setZones(z);
            setEnrichment(e);

            // Stats fetch is non-blocking to prevent "Failed to fetch policies" if daemon/worker is old
            api.getResourceUsage()
                .then(setUsage)
                .catch(err => console.warn('Usage stats unavailable:', err));
        } catch (e) {
            console.error('Failed to fetch policies:', e);
            toast.error('Failed to fetch policies. Is the daemon running?');
        }
    }

    // --- Zones ---
    async function addZone(pattern: string) {
        if (!pattern) return;

        let normalized = pattern.trim();
        if (normalized.startsWith('~')) {
            normalized = normalized.replace('~', homePath);
        }

        const asteriskCount = (normalized.match(/\*/g) || []).length;
        if (asteriskCount > 1) {
            toast.error("Multiple asterisks are not allowed.");
            return;
        }

        // Check for standalone asterisk
        if (normalized === '*') {
            toast.error("Standalone asterisk is not a valid pattern.");
            return;
        }

        // Check for asterisk in the middle
        if (asteriskCount === 1 && !normalized.startsWith('*') && !normalized.endsWith('*')) {
            toast.error("Asterisk must be at the start or end of the pattern.");
            return;
        }

        toast.promise(
            async () => {
                await api.addZone('red', normalized);
                setNewRed('');
                await fetchData();
            },
            { loading: 'Adding zone...', success: 'Zone added', error: (e) => `Failed: ${e}` }
        );
    }

    async function removeZone(pattern: string) {
        toast.promise(
            async () => {
                await api.removeZone('red', pattern);
                await fetchData();
            },
            { loading: 'Removing zone...', success: `Zone "${pattern}" removed`, error: (e) => `Failed: ${e}` }
        );
    }

    // --- Enrichment ---
    async function addEnrichment(pattern: string) {
        if (!pattern) return;

        let normalized = pattern.trim();
        if (normalized.startsWith('~')) {
            normalized = normalized.replace('~', homePath);
        }

        const asteriskCount = (normalized.match(/\*/g) || []).length;
        if (asteriskCount > 1) {
            toast.error("Multiple asterisks are not allowed.");
            return;
        }

        // Enrichment patterns must end with *
        if (!normalized.endsWith('*')) {
            toast.error("Enrichment pattern must end with '*' (e.g. /usr/bin/python*)");
            return;
        }

        // Check for asterisk in the middle (enrichment must be prefix pattern)
        const withoutTrailing = normalized.slice(0, -1);
        if (withoutTrailing.includes('*')) {
            toast.error("Enrichment pattern can only have asterisk at the end.");
            return;
        }

        toast.promise(
            async () => {
                await api.addEnrichmentPattern(normalized);
                setNewPattern('');
                await fetchData();
            },
            { loading: 'Adding pattern...', success: 'Pattern added', error: (e) => `Failed: ${e}` }
        );
    }

    async function removeEnrichment(pattern: string) {
        toast.promise(
            async () => {
                await api.removeEnrichmentPattern(pattern);
                await fetchData();
            },
            { loading: 'Removing pattern...', success: `Pattern "${pattern}" removed`, error: (e) => `Failed: ${e}` }
        );
    }

    return (
        <div className="space-y-8 pb-10">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 px-1">
                <div className="flex items-center space-x-3">
                    <div className={`p-2.5 rounded-xl shadow-sm ${activeTab === 'zones' ? 'bg-rose-50 text-rose-600' : 'bg-indigo-50 text-indigo-600'}`}>
                        {activeTab === 'zones' ? <FolderLock size={22} /> : <Terminal size={22} />}
                    </div>
                    <div>
                        <h1 className="text-xl font-bold text-zinc-900 tracking-tight">
                            {activeTab === 'zones' ? 'Security Zones' : 'Interpreter Tracing'}
                        </h1>
                        <p className="text-sm text-zinc-500 font-medium">
                            {activeTab === 'zones'
                                ? 'Define paths where unauthorized access is blocked.'
                                : 'Identify script interpreters for argument-based tracing.'}
                        </p>
                    </div>
                </div>
            </div>

            {!isRootActive && (
                <div className="max-w-4xl">
                    <ContextualUnlock
                        description="Modifying security zones or enrichment patterns requires an active root session. Unlock to manage kernel-level protections."
                    />
                </div>
            )}

            <div className="max-w-4xl space-y-6">
                {activeTab === 'zones' ? (
                    <div className="bg-white border border-zinc-200 rounded-2xl p-6 sm:p-8 shadow-sm animate-in fade-in slide-in-from-bottom-4 duration-500">
                        <div className="flex items-center space-x-3 mb-8">
                            <div className="p-2 bg-rose-50 rounded-lg">
                                <ShieldAlert className="text-rose-600" size={20} />
                            </div>
                            <div>
                                <h3 className="text-md font-bold text-zinc-900 uppercase tracking-wider">Protected Zones</h3>
                                <div className="flex flex-wrap gap-2 mt-1">
                                    {usage && (
                                        <>
                                            <UsageBadge label="Prefix" current={usage.zones.prefix.current} max={usage.zones.prefix.max} />
                                            <UsageBadge label="Suffix" current={usage.zones.suffix.current} max={usage.zones.suffix.max} />
                                            <UsageBadge label="Exact" current={usage.zones.exact.current} max={usage.zones.exact.max} />
                                        </>
                                    )}
                                </div>
                            </div>
                        </div>

                        <div className="flex space-x-2 mb-8">
                            <input
                                value={newRed}
                                onChange={(e) => setNewRed(e.target.value)}
                                disabled={!isRootActive}
                                placeholder={isRootActive ? "e.g. *.key, /etc/shadow" : "Authenticate as root to add zones"}
                                className={`flex-1 bg-zinc-50 border rounded-xl px-4 py-2.5 text-sm text-zinc-900 placeholder-zinc-400 focus:ring-4 outline-none transition-all disabled:opacity-50 ${(newRed.match(/\*/g) || []).length > 1 ? 'border-rose-300 focus:ring-rose-500/10 focus:border-rose-500' : 'border-zinc-200 focus:ring-indigo-500/10 focus:border-indigo-500'
                                    }`}
                            />
                            <button
                                onClick={() => addZone(newRed)}
                                disabled={!isRootActive}
                                className="px-4 bg-rose-600 hover:bg-rose-700 text-white rounded-xl transition-all shadow-lg shadow-rose-100 active:scale-95 flex items-center justify-center shrink-0 disabled:opacity-50 disabled:cursor-not-allowed"
                            >
                                <Plus size={20} />
                            </button>
                        </div>
                        <div className="flex justify-between mt-1 mb-8">
                            <p className="text-[10px] text-zinc-500 font-medium italic">
                                {newRed.startsWith('~') ? (
                                    <span className="text-indigo-500 font-bold">Will expand to {homePath}...</span>
                                ) : (newRed.match(/\*/g) || []).length > 1 ? (
                                    <span className="text-rose-500 font-bold">Only 1 asterisk allowed</span>
                                ) : (
                                    "Supports glob patterns (e.g. /home/*/.ssh/**)"
                                )}
                            </p>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                            {zones.red_zones.map((zone) => (
                                <div key={zone} className="flex justify-between items-center p-4 bg-zinc-50 rounded-xl border border-zinc-100 group hover:border-rose-200 hover:bg-rose-50/30 transition-all duration-300">
                                    <div className="flex items-center space-x-3 truncate">
                                        <div className="w-1.5 h-1.5 rounded-full bg-zinc-400 group-hover:scale-125 transition-transform" />
                                        <span className="font-mono text-xs text-zinc-800 truncate">{zone}</span>
                                    </div>
                                    <button
                                        onClick={() => removeZone(zone)}
                                        disabled={!isRootActive}
                                        className="text-zinc-400 hover:text-rose-600 bg-white p-1.5 rounded-lg shadow-sm border border-transparent hover:border-rose-100 transition-all md:opacity-0 group-hover:opacity-100 active:scale-95 disabled:hover:text-zinc-400 disabled:cursor-not-allowed"
                                    >
                                        <Trash2 size={14} />
                                    </button>
                                </div>
                            ))}
                            {zones.red_zones.length === 0 && (
                                <div className="col-span-full py-16 text-center">
                                    <div className="inline-flex p-4 bg-zinc-50 rounded-full mb-4">
                                        <FolderLock size={32} className="text-zinc-200" />
                                    </div>
                                    <p className="text-zinc-400 text-sm font-medium italic">No protected zones defined yet.</p>
                                </div>
                            )}
                        </div>
                    </div>
                ) : (
                    <div className="bg-white border border-zinc-200 rounded-2xl p-6 sm:p-8 shadow-sm animate-in fade-in slide-in-from-bottom-4 duration-500">
                        <div className="flex items-center space-x-3 mb-8">
                            <div className="p-2 bg-indigo-50 rounded-lg">
                                <Code2 className="text-indigo-600" size={20} />
                            </div>
                            <div>
                                <h3 className="text-md font-bold text-zinc-900 uppercase tracking-wider">Interpreter Tracing</h3>
                                <div className="flex gap-2 mt-1">
                                    {usage && (
                                        <UsageBadge label="Capacity" current={usage.enrichment.current} max={usage.enrichment.max} />
                                    )}
                                </div>
                            </div>
                        </div>

                        <div className="flex space-x-2 mb-8">
                            <input
                                value={newPattern}
                                onChange={(e) => setNewPattern(e.target.value)}
                                disabled={!isRootActive}
                                placeholder={isRootActive ? "e.g. /usr/bin/python*, */node" : "Authenticate as root to add patterns"}
                                className={`flex-1 bg-zinc-50 border rounded-xl px-4 py-2.5 text-sm text-zinc-900 placeholder-zinc-400 focus:ring-4 outline-none transition-all disabled:opacity-50 ${(newPattern.match(/\*/g) || []).length > 1 ? 'border-rose-300 focus:ring-rose-500/10 focus:border-rose-500' : 'border-zinc-200 focus:ring-indigo-500/10 focus:border-indigo-500'
                                    }`}
                            />
                            <button
                                onClick={() => addEnrichment(newPattern)}
                                disabled={!isRootActive}
                                className="px-4 bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl transition-all shadow-lg shadow-indigo-100 active:scale-95 flex items-center justify-center shrink-0 disabled:opacity-50 disabled:cursor-not-allowed"
                            >
                                <Plus size={20} />
                            </button>
                        </div>
                        <div className="flex justify-between mt-1 mb-8">
                            <p className="text-[10px] text-zinc-500 font-medium italic">
                                {newPattern.startsWith('~') ? (
                                    <span className="text-indigo-500 font-bold">Will expand to {homePath}...</span>
                                ) : (newPattern.match(/\*/g) || []).length > 1 ? (
                                    <span className="text-rose-500 font-bold">Only 1 asterisk allowed</span>
                                ) : (
                                    "Commands are hashed to verify script identity."
                                )}
                            </p>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                            {enrichment.enrichment_patterns.map((pattern) => (
                                <div key={pattern} className="flex justify-between items-center p-4 bg-zinc-50 rounded-xl border border-zinc-100 group hover:border-indigo-200 hover:bg-indigo-50/30 transition-all duration-300">
                                    <div className="flex items-center space-x-3 truncate">
                                        <div className="w-1.5 h-1.5 rounded-full bg-indigo-400 group-hover:scale-125 transition-transform" />
                                        <span className="font-mono text-xs text-indigo-800 truncate">{pattern}</span>
                                    </div>
                                    <button
                                        onClick={() => removeEnrichment(pattern)}
                                        disabled={!isRootActive}
                                        className="text-zinc-400 hover:text-indigo-600 bg-white p-1.5 rounded-lg shadow-sm border border-transparent hover:border-indigo-100 transition-all md:opacity-0 group-hover:opacity-100 active:scale-95 disabled:hover:text-zinc-400 disabled:cursor-not-allowed"
                                    >
                                        <Trash2 size={14} />
                                    </button>
                                </div>
                            ))}
                            {enrichment.enrichment_patterns.length === 0 && (
                                <div className="col-span-full py-16 text-center">
                                    <div className="inline-flex p-4 bg-zinc-50 rounded-full mb-4">
                                        <Terminal size={32} className="text-zinc-200" />
                                    </div>
                                    <p className="text-zinc-400 text-sm font-medium italic">No interpreter patterns defined yet.</p>
                                </div>
                            )}
                        </div>
                    </div>
                )}
            </div>

            {/* Context Info */}
            <div className="max-w-4xl p-6 bg-zinc-50 rounded-2xl border border-zinc-200/50 flex items-start space-x-4">
                <div className="p-2 bg-white rounded-xl border border-zinc-200 shadow-xs">
                    <History size={18} className="text-zinc-400" />
                </div>
                <div>
                    <h4 className="text-xs font-bold text-zinc-900 uppercase tracking-widest mb-1">Implementation Note</h4>
                    <p className="text-xs text-zinc-500 font-medium leading-relaxed">
                        Changes to security zones and interpreters take effect immediately in the kernel. Existing processes are not affected until they trigger a new security event.
                        <strong> Script interpreters</strong> are used to ensure that even if the executor is authorized, the script contents are verified.
                    </p>
                </div>
            </div>
        </div>
    );
}

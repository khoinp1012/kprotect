import { useState, useEffect } from 'react';
import { Bell, Plus, Trash2, Power, ExternalLink, FileCode, Clock, Activity, AlertTriangle, ShieldCheck, TrendingUp, CheckCircle2, XCircle, Timer } from 'lucide-react';
import { api } from '../api';
import { toast } from 'sonner';
import { useGlobal } from '../context/GlobalContext';
import { ContextualUnlock } from '../components/ContextualUnlock';
import { NotificationRule } from '../types';

import { homeDir } from '@tauri-apps/api/path';

// Helper function to format time ago
function formatTimeAgo(timestamp: number | null): string {
    if (!timestamp) return 'Never';
    const now = Math.floor(Date.now() / 1000);
    const diff = now - timestamp;

    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 86400)}d ago`;
}

export function Notifications() {
    const { isRootActive, blockedAlertsEnabled, setBlockedAlertsEnabled, authorizedAlertsEnabled, setAuthorizedAlertsEnabled } = useGlobal();
    const [rules, setRules] = useState<NotificationRule[]>([]);
    const [isLoading, setIsLoading] = useState(true);
    const [isAddModalOpen, setIsAddModalOpen] = useState(false);
    const [homePath, setHomePath] = useState('');

    useEffect(() => {
        homeDir().then(setHomePath).catch(console.error);
    }, []);

    // Form state
    const [newName, setNewName] = useState('');
    const [newEvents, setNewEvents] = useState<string[]>(['Blocked']);
    const [newPath, setNewPath] = useState('');
    const [newAction, setNewAction] = useState<'Script' | 'Webhook'>('Script');
    const [newDest, setNewDest] = useState('');
    const [newTimeout, setNewTimeout] = useState(30);

    const fetchRules = async () => {
        setIsLoading(true);
        try {
            const data = await api.getNotificationRules();
            setRules(Array.isArray(data) ? data : []);
        } catch (e) {
            console.error(e);
            toast.error("Failed to load notification rules");
        } finally {
            setIsLoading(false);
        }
    };

    useEffect(() => {
        fetchRules();
    }, []);

    const handleToggle = async (id: number, enabled: boolean) => {
        try {
            await api.toggleNotificationRule(id, enabled);
            toast.success(`Rule ${enabled ? 'enabled' : 'disabled'}`);
            fetchRules();
        } catch (e: any) {
            toast.error(e.toString());
        }
    };

    const handleDelete = async (id: number, ruleName: string) => {
        try {
            await api.removeNotificationRule(id);
            toast.success(`Rule "${ruleName}" removed`);
            fetchRules();
        } catch (e: any) {
            toast.error(e.toString());
        }
    };

    const handleAdd = async (e: React.FormEvent) => {
        e.preventDefault();

        // Expansion and Validation
        let path = newPath.trim();
        if (path.startsWith('~')) {
            path = path.replace('~', homePath); // Inference from workspace
        }

        const asteriskCount = (path.match(/\*/g) || []).length;
        if (asteriskCount > 1) {
            toast.error("Multiple asterisks are not allowed.");
            return;
        }

        try {
            await api.addNotificationRule({
                name: newName,
                events: newEvents.join(','),
                path: path || null,
                action: newAction,
                dest: newDest,
                timeout: newTimeout
            });
            toast.success("Notification rule added");
            setIsAddModalOpen(false);
            // Reset form
            setNewName('');
            setNewEvents(['Blocked']);
            setNewPath('');
            setNewDest('');
            fetchRules();
        } catch (e: any) {
            toast.error(e.toString());
        }
    };

    const getEventIcon = (type: string) => {
        switch (type) {
            case 'Verified': return <ShieldCheck className="text-emerald-500" size={14} />;
            case 'Blocked': return <AlertTriangle className="text-rose-500" size={14} />;
            default: return null;
        }
    };

    return (
        <div className="space-y-6">
            <div className="flex justify-between items-center">
                <div>
                    <h2 className="text-2xl font-bold text-zinc-900 tracking-tight">Notification Rules</h2>
                    <p className="text-zinc-500 text-sm mt-1">Configure automated actions for security events.</p>
                </div>
                <div className="flex items-center space-x-3">
                    <div className="flex items-center space-x-3 bg-white border border-zinc-200 px-4 py-2.5 rounded-xl shadow-sm">
                        <AlertTriangle size={18} className={blockedAlertsEnabled ? "text-rose-600" : "text-zinc-400"} />
                        <span className="text-sm font-bold text-zinc-700 tracking-tight">Desktop Blocked Alerts</span>
                        <button
                            onClick={() => setBlockedAlertsEnabled(!blockedAlertsEnabled)}
                            className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none ${blockedAlertsEnabled ? 'bg-rose-600' : 'bg-zinc-300'}`}
                        >
                            <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${blockedAlertsEnabled ? 'translate-x-6' : 'translate-x-1'}`} />
                        </button>
                    </div>

                    <div className="flex items-center space-x-3 bg-white border border-zinc-200 px-4 py-2.5 rounded-xl shadow-sm">
                        <ShieldCheck size={18} className={authorizedAlertsEnabled ? "text-emerald-600" : "text-zinc-400"} />
                        <span className="text-sm font-bold text-zinc-700 tracking-tight">Desktop Verified Alerts</span>
                        <button
                            onClick={() => setAuthorizedAlertsEnabled(!authorizedAlertsEnabled)}
                            className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none ${authorizedAlertsEnabled ? 'bg-emerald-600' : 'bg-zinc-300'}`}
                        >
                            <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${authorizedAlertsEnabled ? 'translate-x-6' : 'translate-x-1'}`} />
                        </button>
                    </div>

                    <button
                        onClick={() => setIsAddModalOpen(true)}
                        disabled={!isRootActive}
                        className="flex items-center px-4 py-2 bg-indigo-600 text-white rounded-lg font-semibold text-sm hover:bg-indigo-700 transition-colors shadow-sm disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                        <Plus size={18} className="mr-2" />
                        New Rule
                    </button>
                </div>
            </div>

            {!isRootActive && (
                <ContextualUnlock
                    description="Notification management (adding, toggling, deleting rules) requires an active root session. Unlock to manage alert automation."
                />
            )}

            {isLoading ? (
                <div className="py-20 text-center">
                    <div className="inline-block animate-spin rounded-full h-8 w-8 border-4 border-zinc-200 border-t-indigo-600"></div>
                </div>
            ) : rules.length === 0 ? (
                <div className="py-20 text-center bg-zinc-50 rounded-2xl border-2 border-dashed border-zinc-200">
                    <Bell size={48} className="mx-auto text-zinc-300 mb-4" />
                    <h3 className="text-lg font-semibold text-zinc-900">No notification rules</h3>
                    <p className="text-zinc-500 max-w-sm mx-auto mt-1">Create rules to trigger scripts or webhooks when specific security events occur.</p>
                </div>
            ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {rules.map(rule => (
                        <div key={rule.id} className={`p-6 rounded-2xl border transition-all ${rule.enabled ? 'bg-white border-zinc-200' : 'bg-zinc-50 border-zinc-100 opacity-75'}`}>
                            <div className="flex justify-between items-start mb-4">
                                <div className="flex items-center space-x-3">
                                    <div className={`p-2 rounded-lg ${rule.enabled ? 'bg-indigo-50 text-indigo-600' : 'bg-zinc-200 text-zinc-500'}`}>
                                        {rule.action_type === 'Script' ? <FileCode size={20} /> : <ExternalLink size={20} />}
                                    </div>
                                    <div>
                                        <h3 className="font-bold text-zinc-900 uppercase tracking-tight text-sm">{rule.name}</h3>
                                        <div className="flex items-center space-x-2 mt-1">
                                            {rule.event_types.map(et => (
                                                <span key={et} className="inline-flex items-center px-2 py-0.5 rounded-full bg-zinc-100 text-[10px] font-bold text-zinc-600">
                                                    <span className="mr-1">{getEventIcon(et)}</span>
                                                    {et}
                                                </span>
                                            ))}
                                        </div>
                                    </div>
                                </div>
                                <div className="flex items-center space-x-2">
                                    <button
                                        onClick={() => handleToggle(rule.id, !rule.enabled)}
                                        disabled={!isRootActive}
                                        className={`p-2 rounded-lg transition-colors ${rule.enabled ? 'text-emerald-600 hover:bg-emerald-50' : 'text-zinc-400 hover:bg-zinc-100'}`}
                                        title={rule.enabled ? "Disable Rule" : "Enable Rule"}
                                    >
                                        <Power size={18} />
                                    </button>
                                    <button
                                        onClick={() => handleDelete(rule.id, rule.name)}
                                        disabled={!isRootActive}
                                        className="p-2 text-rose-600 hover:bg-rose-50 rounded-lg transition-colors"
                                        title="Delete Rule"
                                    >
                                        <Trash2 size={18} />
                                    </button>
                                </div>
                            </div>

                            <div className="space-y-3 mt-4 pt-4 border-t border-zinc-100">
                                <div className="flex items-center text-xs text-zinc-600">
                                    <span className="w-20 font-medium uppercase tracking-widest text-[10px]">Destination</span>
                                    <code className="bg-zinc-100 px-2 py-1 rounded truncate flex-1 font-mono text-indigo-600">{rule.destination}</code>
                                </div>
                                {rule.path_pattern && (
                                    <div className="flex items-center text-xs text-zinc-600">
                                        <span className="w-20 font-medium uppercase tracking-widest text-[10px]">Filter</span>
                                        <span className="font-mono text-amber-600">{rule.path_pattern}</span>
                                    </div>
                                )}

                                {/* Stats Section */}
                                {rule.trigger_count > 0 && (() => {
                                    const successRate = rule.trigger_count > 0 ? (rule.success_count / rule.trigger_count) * 100 : 0;
                                    const avgMs = rule.trigger_count > 0 ? rule.total_execution_ms / rule.trigger_count : 0;

                                    return (
                                        <div className="grid grid-cols-2 gap-2 mt-3">
                                            <div className="bg-zinc-50 rounded-lg p-2">
                                                <div className="flex items-center justify-between">
                                                    <span className="text-[9px] uppercase tracking-widest font-bold text-zinc-400">Success Rate</span>
                                                    <TrendingUp size={10} className={successRate >= 95 ? "text-emerald-500" : successRate >= 80 ? "text-amber-500" : "text-rose-500"} />
                                                </div>
                                                <div className={`text-lg font-bold mt-0.5 ${successRate >= 95 ? 'text-emerald-600' :
                                                    successRate >= 80 ? 'text-amber-600' :
                                                        'text-rose-600'
                                                    }`}>
                                                    {successRate.toFixed(1)}%
                                                </div>
                                                <div className="flex items-center space-x-2 mt-1 text-[9px] text-zinc-500">
                                                    <span className="flex items-center"><CheckCircle2 size={10} className="mr-0.5 text-emerald-500" />{rule.success_count}</span>
                                                    {rule.failure_count > 0 && <span className="flex items-center"><XCircle size={10} className="mr-0.5 text-rose-500" />{rule.failure_count}</span>}
                                                    {rule.timeout_count > 0 && <span className="flex items-center"><Timer size={10} className="mr-0.5 text-amber-500" />{rule.timeout_count}</span>}
                                                </div>
                                            </div>

                                            <div className="bg-zinc-50 rounded-lg p-2">
                                                <div className="flex items-center justify-between">
                                                    <span className="text-[9px] uppercase tracking-widest font-bold text-zinc-400">Avg Time</span>
                                                    <Clock size={10} className="text-indigo-500" />
                                                </div>
                                                <div className="text-lg font-bold text-indigo-600 mt-0.5">
                                                    {avgMs.toFixed(0)}ms
                                                </div>
                                                <div className="text-[9px] text-zinc-500 mt-1">
                                                    {rule.trigger_count} trigger{rule.trigger_count !== 1 ? 's' : ''}
                                                </div>
                                            </div>
                                        </div>
                                    );
                                })()}

                                <div className="flex items-center justify-between text-[11px] text-zinc-400 font-medium mt-2">
                                    <div className="flex items-center space-x-4">
                                        <span className="flex items-center">
                                            <Activity size={12} className="mr-1" />
                                            {rule.trigger_count === 0 ? 'Never triggered' : formatTimeAgo(rule.last_triggered)}
                                        </span>
                                    </div>
                                    <span className="bg-zinc-100 px-2 py-0.5 rounded uppercase tracking-widest text-[9px] font-bold">{rule.action_type}</span>
                                </div>
                            </div>
                        </div>
                    ))}
                </div>
            )}

            {/* Add Modal */}
            {isAddModalOpen && (
                <div className="fixed inset-0 bg-black/40 backdrop-blur-sm flex items-center justify-center z-50 p-6">
                    <div className="bg-white rounded-3xl shadow-2xl w-full max-w-xl overflow-hidden border border-zinc-200">
                        <form onSubmit={handleAdd}>
                            <div className="p-8 space-y-6">
                                <div className="flex justify-between items-center">
                                    <h3 className="text-xl font-bold text-zinc-900 tracking-tight">Create Notification Rule</h3>
                                    <button onClick={() => setIsAddModalOpen(false)} className="text-zinc-400 hover:text-zinc-900">
                                        <Plus size={24} className="rotate-45" />
                                    </button>
                                </div>

                                <div className="space-y-4">
                                    <div>
                                        <label className="block text-xs font-bold text-zinc-500 uppercase tracking-widest mb-1.5 ml-1">Rule Name</label>
                                        <input
                                            required
                                            value={newName}
                                            onChange={e => setNewName(e.target.value)}
                                            placeholder="e.g. Alert Admin on Blocked Access"
                                            className="w-full bg-zinc-50 border border-zinc-200 rounded-xl px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all font-medium"
                                        />
                                    </div>

                                    <div className="grid grid-cols-2 gap-4">
                                        <div>
                                            <label className="block text-xs font-bold text-zinc-500 uppercase tracking-widest mb-1.5 ml-1">Action Type</label>
                                            <div className="flex items-center space-x-2">
                                                {['Script', 'Webhook'].map(type => (
                                                    <button
                                                        key={type}
                                                        type="button"
                                                        onClick={() => setNewAction(type as any)}
                                                        className={`flex-1 px-3 py-2 rounded-lg text-xs font-bold transition-all border ${newAction === type
                                                            ? 'bg-indigo-600 border-indigo-600 text-white'
                                                            : 'bg-zinc-50 border-zinc-200 text-zinc-500 hover:border-zinc-300'
                                                            }`}
                                                    >
                                                        {type}
                                                    </button>
                                                ))}
                                            </div>
                                        </div>
                                        <div>
                                            <label className="block text-xs font-bold text-zinc-500 uppercase tracking-widest mb-1.5 ml-1">Timeout (seconds)</label>
                                            <input
                                                type="number"
                                                value={newTimeout}
                                                onChange={e => setNewTimeout(parseInt(e.target.value))}
                                                className="w-full bg-zinc-50 border border-zinc-200 rounded-xl px-4 py-3 text-sm focus:outline-none"
                                            />
                                        </div>
                                    </div>

                                    <div>
                                        <label className="block text-xs font-bold text-zinc-500 uppercase tracking-widest mb-1.5 ml-1">Event Types</label>
                                        <div className="flex items-center space-x-2">
                                            {['Verified', 'Blocked'].map(type => (
                                                <button
                                                    key={type}
                                                    type="button"
                                                    onClick={() => {
                                                        if (newEvents.includes(type)) {
                                                            setNewEvents(newEvents.filter(et => et !== type));
                                                        } else {
                                                            setNewEvents([...newEvents, type]);
                                                        }
                                                    }}
                                                    className={`px-3 py-2 rounded-lg text-xs font-bold transition-all border ${newEvents.includes(type)
                                                        ? 'bg-indigo-600 border-indigo-600 text-white'
                                                        : 'bg-zinc-50 border-zinc-200 text-zinc-500 hover:border-zinc-300'
                                                        }`}
                                                >
                                                    {type}
                                                </button>
                                            ))}
                                        </div>
                                    </div>

                                    <div>
                                        <label className="block text-xs font-bold text-zinc-500 uppercase tracking-widest mb-1.5 ml-1">Destination ({newAction === 'Script' ? 'Path' : 'URL'})</label>
                                        <input
                                            required
                                            value={newDest}
                                            onChange={e => setNewDest(e.target.value)}
                                            placeholder={newAction === 'Script' ? '/opt/kprotect/scripts/alert.sh' : 'https://hooks.slack.com/...'}
                                            className="w-full bg-zinc-50 border border-zinc-200 rounded-xl px-4 py-3 text-sm focus:outline-none font-mono"
                                        />
                                    </div>

                                    <div>
                                        <label className="block text-xs font-bold text-zinc-500 uppercase tracking-widest mb-1.5 ml-1">Path Pattern (Optional)</label>
                                        <input
                                            value={newPath}
                                            onChange={e => setNewPath(e.target.value)}
                                            placeholder="e.g. /etc/*.conf or /home/*"
                                            className={`w-full bg-zinc-50 border rounded-xl px-4 py-3 text-sm focus:outline-none font-mono transition-colors ${(newPath.match(/\*/g) || []).length > 1 ? 'border-rose-300 focus:border-rose-500' : 'border-zinc-200 focus:border-indigo-500'
                                                }`}
                                        />
                                        <div className="flex justify-between mt-1.5 ml-1">
                                            <p className="text-[10px] text-zinc-400 uppercase tracking-wider font-bold">Asterisks (*) at start or end.</p>
                                            {newPath.startsWith('~') && (
                                                <p className="text-[10px] text-indigo-500 font-bold animate-pulse">Will expand to {homePath}...</p>
                                            )}
                                            {(newPath.match(/\*/g) || []).length > 1 && (
                                                <p className="text-[10px] text-rose-500 font-bold">Only 1 asterisk allowed</p>
                                            )}
                                        </div>
                                    </div>
                                </div>

                                {/* Helper Text */}
                                <div className="bg-indigo-50/50 rounded-xl p-4 border border-indigo-100">
                                    <p className="text-[10px] uppercase tracking-widest font-bold text-indigo-400 mb-2">
                                        {newAction === 'Script' ? 'Environment Variables' : 'JSON Payload'}
                                    </p>
                                    <div className="space-y-1">
                                        {newAction === 'Script' ? (
                                            <>
                                                <p className="text-xs text-indigo-900"><code className="bg-white px-1 py-0.5 rounded border border-indigo-100 text-[10px] mr-1">KPROTECT_EVENT_JSON</code> Full event data</p>
                                                <p className="text-xs text-indigo-900"><code className="bg-white px-1 py-0.5 rounded border border-indigo-100 text-[10px] mr-1">KPROTECT_STATUS</code> Verified / Blocked</p>
                                                <p className="text-xs text-indigo-900"><code className="bg-white px-1 py-0.5 rounded border border-indigo-100 text-[10px] mr-1">KPROTECT_TARGET</code> Accessed file path</p>
                                            </>
                                        ) : (
                                            <p className="text-xs text-indigo-900 font-mono text-[10px]">
                                                {`{ "id": 123, "status": "Verified", "target": "/etc/passwd", ... }`}
                                            </p>
                                        )}
                                    </div>
                                </div>
                            </div>

                            <div className="p-6 bg-zinc-50 border-t border-zinc-200 flex justify-end space-x-3">
                                <button
                                    type="button"
                                    onClick={() => setIsAddModalOpen(false)}
                                    className="px-6 py-2.5 text-sm font-bold text-zinc-600 hover:text-zinc-900 transition-colors uppercase tracking-widest"
                                >
                                    Cancel
                                </button>
                                <button
                                    type="submit"
                                    className="px-8 py-2.5 bg-indigo-600 text-white rounded-xl font-bold text-sm hover:bg-indigo-700 transition-all shadow-md shadow-indigo-200 uppercase tracking-widest"
                                >
                                    Create Rule
                                </button>
                            </div>
                        </form>
                    </div>
                </div >
            )
            }
        </div >
    );
}


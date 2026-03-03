import { useState, useEffect } from 'react';
import { Activity, Shield, BarChart3, Fingerprint, Zap, ShieldCheck, AlertTriangle } from 'lucide-react';
import { api, DaemonStatus, SystemInfo } from '../api';
import { useGlobal } from '../context/GlobalContext';

export function Dashboard() {
    const { events, elevationEvents, isRootActive } = useGlobal();
    const [status, setStatus] = useState<DaemonStatus | null>(null);
    const [system, setSystem] = useState<SystemInfo | null>(null);
    const [uptime, setUptime] = useState<number>(0);
    const [loading, setLoading] = useState(true);

    // Toggle loading states
    const [togglingEngine, setTogglingEngine] = useState(false);
    const [togglingProtection, setTogglingProtection] = useState(false);
    const [togglingSudo, setTogglingSudo] = useState(false);

    useEffect(() => {
        loadData();
        const dataInterval = setInterval(loadData, 5000);

        // Real-time uptime counter
        const uptimeInterval = setInterval(() => {
            setUptime(prev => prev + 1);
        }, 1000);

        return () => {
            clearInterval(dataInterval);
            clearInterval(uptimeInterval);
        };
    }, []);

    async function loadData() {
        try {
            const [s, sys] = await Promise.all([
                api.getDaemonStatus(),
                api.getSystemInfo()
            ]);
            setStatus(s);
            setSystem(sys);
            if (s) setUptime(s.uptime_seconds);
        } catch (err) {
            console.error('Failed to load dashboard data:', err);
        } finally {
            setLoading(false);
        }
    }

    const handleToggleEngine = async () => {
        if (!system || togglingEngine || !isRootActive) return;
        setTogglingEngine(true);
        try {
            await api.setEngineEnabled(!system.engine_enabled);
            await loadData();
        } finally {
            setTogglingEngine(false);
        }
    };

    const handleToggleProtection = async () => {
        if (!system || togglingProtection || !isRootActive) return;
        setTogglingProtection(true);
        try {
            await api.setFileProtection(!system.file_protection_enabled);
            await loadData();
        } finally {
            setTogglingProtection(false);
        }
    };

    const handleToggleSudo = async () => {
        if (!system || togglingSudo || !isRootActive) return;
        setTogglingSudo(true);
        try {
            await api.setSudoBypass(!system.sudo_bypass_enabled);
            await loadData();
        } finally {
            setTogglingSudo(false);
        }
    };

    if (loading && !status) {
        return (
            <div className="flex items-center justify-center h-full">
                <Activity className="animate-spin text-indigo-600" size={32} />
            </div>
        );
    }

    // Helper to get unique recent items for the dashboard cards
    const getUniqueRecent = (list: any[], limit: number) => {
        const unique: any[] = [];
        const seen = new Set();

        for (const event of list) {
            const key = `${event.status}-${event.path}-${JSON.stringify(event.chain)}`;
            if (!seen.has(key)) {
                unique.push(event);
                seen.add(key);
            }
            if (unique.length >= limit) break;
        }
        return unique;
    };

    // Filter recent file activity (Blocked or Verified)
    const recentFileActivity = getUniqueRecent(
        events.filter(e => e.status === 'Blocked' || e.status === 'Verified'),
        3
    );

    // Recent sudo activity - include all sudo-related statuses
    const recentSudoActivity = getUniqueRecent(
        elevationEvents.filter(e => e.status !== 'Birth' && e.status !== 'Exit'),
        3
    );

    return (
        <div className="p-6 space-y-6">
            {!system?.engine_enabled && (
                <div className="bg-amber-50 border border-amber-200 rounded-xl p-4 flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                        <AlertTriangle className="text-amber-600" size={20} />
                        <div>
                            <p className="text-sm font-bold text-amber-900">Protection Engine is Paused</p>
                            <p className="text-xs text-amber-700">Lineage tracking is active, but enforcement and bypass features are currently disabled.</p>
                        </div>
                    </div>
                    <button
                        onClick={handleToggleEngine}
                        disabled={!isRootActive || togglingEngine}
                        className="px-3 py-1.5 bg-amber-600 text-white text-xs font-bold rounded-lg hover:bg-amber-700 transition-colors disabled:opacity-50"
                    >
                        Resume Engine
                    </button>
                </div>
            )}

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {/* 1. Daemon Status Card */}
                <Card
                    title="Daemon Status"
                    icon={<Activity className="text-blue-600" size={20} />}
                    subtitle="Operational Metrics"
                    status={status?.ebpf_loaded ? "success" : "warning"}
                >
                    <div className="space-y-4 mt-4">
                        <div className="flex justify-between items-center text-sm">
                            <span className="text-zinc-500 font-medium">Uptime</span>
                            <span className="font-mono font-bold text-zinc-900">{formatUptime(uptime)}</span>
                        </div>
                        <div className="flex justify-between items-center text-sm">
                            <span className="text-zinc-500 font-medium">Active Sessions</span>
                            <span className="font-mono font-bold text-zinc-900">{status?.active_connections || 0}</span>
                        </div>
                        <div className="flex justify-between items-center text-sm">
                            <span className="text-zinc-500 font-medium">Socket</span>
                            <span className="font-mono text-[10px] bg-zinc-50 px-1.5 py-0.5 rounded border border-zinc-100 max-w-[120px] truncate" title={status?.socket_path}>
                                {status?.socket_path || "/run/kprotect.sock"}
                            </span>
                        </div>
                        <div className="pt-3 border-t border-zinc-100">
                            <Stat
                                label="eBPF Probes"
                                value={status?.ebpf_loaded ? "Active" : "Issues"}
                                color={status?.ebpf_loaded ? "text-emerald-600" : "text-amber-600"}
                                icon={<ShieldCheck size={14} className={status?.ebpf_loaded ? "text-emerald-500" : "text-amber-500"} />}
                            />
                        </div>
                    </div>
                </Card>

                {/* 2. File Protection Activity Card */}
                <Card
                    title="File Protection"
                    icon={<Shield className="text-emerald-600" size={20} />}
                    subtitle={system?.file_protection_enabled ? "Enforcement Active" : "Protection Disabled"}
                    status={system?.file_protection_enabled ? "success" : "warning"}
                    toggle={
                        <Switch
                            enabled={system?.file_protection_enabled ?? false}
                            onChange={handleToggleProtection}
                            loading={togglingProtection}
                            disabled={!isRootActive || !system?.engine_enabled}
                            activeColor="bg-emerald-600"
                            label="Toggle File Protection"
                        />
                    }
                >
                    <div className="space-y-3 mt-4">
                        <div className="flex justify-between items-center mb-1">
                            <span className="text-[10px] font-bold text-zinc-400 uppercase tracking-widest">Recent Activity</span>
                        </div>
                        {recentFileActivity.length > 0 ? (
                            <div className="space-y-2">
                                {recentFileActivity.map(event => {
                                    const friendlyStatus = event.status === 'Verified' ? 'Authorized' : 'Blocked';
                                    const fileName = event.path.split('/').pop() || "unknown";
                                    const processName = event.comm || "unknown";

                                    return (
                                        <ActivityRow
                                            key={event.id}
                                            icon={event.status === 'Blocked' ? <AlertTriangle size={12} className="text-rose-500" /> : <ShieldCheck size={12} className="text-emerald-500" />}
                                            text={`${processName} → ${fileName}`}
                                            subtext={friendlyStatus}
                                        />
                                    );
                                })}
                            </div>
                        ) : (
                            <p className="text-[10px] text-zinc-400 italic py-2">No recent file events</p>
                        )}
                        <div className="pt-3 border-t border-zinc-100 grid grid-cols-2 gap-3">
                            <Stat label="Blocked" value={system?.events_blocked.toString() || "0"} color="text-rose-600" />
                            <Stat label="Verified" value={system?.events_verified.toString() || "0"} color="text-emerald-600" />
                        </div>
                    </div>
                </Card>

                {/* 2. Quick Sudo Activity Card */}
                <Card
                    title="Quick Sudo"
                    icon={<Zap className="text-amber-600" size={20} />}
                    subtitle={system?.sudo_bypass_enabled ? "Bypass Engine Active" : "Bypass Disabled"}
                    status={system?.sudo_bypass_enabled ? "success" : "warning"}
                    toggle={
                        <Switch
                            enabled={system?.sudo_bypass_enabled ?? false}
                            onChange={handleToggleSudo}
                            loading={togglingSudo}
                            disabled={!isRootActive || !system?.engine_enabled}
                            activeColor="bg-amber-600"
                            label="Toggle Sudo Bypass"
                        />
                    }
                >
                    <div className="space-y-3 mt-4">
                        <div className="flex justify-between items-center mb-1">
                            <span className="text-[10px] font-bold text-zinc-400 uppercase tracking-widest">Recent Elevations</span>
                        </div>
                        {recentSudoActivity.length > 0 ? (
                            <div className="space-y-2">
                                {recentSudoActivity.map(event => {
                                    let statusLabel = "Requested";
                                    let statusColor = "text-amber-500";

                                    if (event.status === 'Elevation') {
                                        statusLabel = "Bypassed";
                                        statusColor = "text-emerald-500";
                                    } else if (event.status === 'Blocked Elevation') {
                                        statusLabel = "Blocked";
                                        statusColor = "text-rose-500";
                                    } else if (event.status === 'Standard Elevation') {
                                        statusLabel = "Password Required";
                                        statusColor = "text-amber-500";
                                    } else if (event.status.startsWith('Sudo Launch')) {
                                        statusLabel = "Sudo Started";
                                        statusColor = "text-indigo-500";
                                    }

                                    return (
                                        <ActivityRow
                                            key={event.id}
                                            icon={<Fingerprint size={12} className={statusColor} />}
                                            text={event.path.split('/').pop() || "sudo"}
                                            subtext={statusLabel}
                                        />
                                    );
                                })}
                            </div>
                        ) : (
                            <p className="text-[10px] text-zinc-400 italic py-2">No recent elevations</p>
                        )}
                        <div className="pt-3 border-t border-zinc-100 grid grid-cols-3 gap-2">
                            <Stat label="Rules" value={system?.sudo_rules_count.toString() || "0"} />
                            <Stat label="Bypassed" value={system?.sudo_events_verified.toString() || "0"} color="text-emerald-600" />
                            <Stat label="Blocked" value={system?.sudo_events_blocked.toString() || "0"} color="text-rose-600" />
                        </div>
                    </div>
                </Card>
            </div>

            {/* Resource Usage Section */}
            <div className="bg-white border border-zinc-200 rounded-xl p-6 shadow-sm">
                <div className="flex items-center space-x-3 mb-6">
                    <div className="p-2 bg-zinc-50 rounded-lg">
                        <BarChart3 className="text-indigo-600" size={20} />
                    </div>
                    <div>
                        <h3 className="text-lg font-bold text-zinc-900 tracking-tight">System Resources</h3>
                        <p className="text-sm text-zinc-500">Kernel map utilization and log storage metrics</p>
                    </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                    {system?.ebpf_maps && Object.entries(system.ebpf_maps)
                        .map(([name, stats]) => {
                            let displayName = name;
                            if (name === 'process_signatures') displayName = 'Process Lineage';
                            if (name === 'authorized_signatures') displayName = 'Authorized Chains';

                            return (
                                <MapProgress key={name} name={displayName} size={stats.size} capacity={stats.capacity} />
                            );
                        })}
                    <StorageCard name="Event Log" size={system?.event_log_size_bytes || 0} />
                    <StorageCard name="Audit Log" size={system?.audit_log_size_bytes || 0} />
                </div>
            </div>

        </div>

    );
}

function Card({ title, icon, subtitle, children, status, toggle }: any) {
    return (
        <div className="bg-white border border-zinc-200 rounded-2xl p-6 shadow-sm hover:shadow-md transition-all">
            <div className="flex justify-between items-center mb-1">
                <div className="flex items-center space-x-3">
                    <div className="p-2.5 bg-zinc-50 rounded-xl border border-zinc-100 shadow-sm">
                        {icon}
                    </div>
                    <div>
                        <h3 className="font-bold text-zinc-900 tracking-tight">{title}</h3>
                        <div className="flex items-center mt-0.5">
                            {status && (
                                <div className={`w-1.5 h-1.5 rounded-full mr-2 ${status === 'success' ? 'bg-emerald-500' : status === 'warning' ? 'bg-amber-500' : 'bg-rose-500'} ${status === 'success' ? 'animate-pulse' : ''}`} />
                            )}
                            <p className="text-[10px] font-bold text-zinc-500 uppercase tracking-wider">{subtitle}</p>
                        </div>
                    </div>
                </div>
                {toggle}
            </div>
            {children}
        </div>
    );
}

function ActivityRow({ icon, text, subtext }: { icon: any, text: string, subtext: string }) {
    return (
        <div className="flex items-center justify-between p-2 bg-zinc-50 rounded-lg border border-zinc-100">
            <div className="flex items-center space-x-2 overflow-hidden">
                <div className="p-1.5 bg-white rounded-md shadow-xs flex-shrink-0">
                    {icon}
                </div>
                <span className="text-xs font-semibold text-zinc-700 truncate">{text}</span>
            </div>
            <span className="text-[9px] font-bold text-zinc-400 uppercase ml-2">{subtext}</span>
        </div>
    );
}

function Switch({ enabled, onChange, loading, disabled, activeColor = "bg-indigo-600", label }: any) {
    return (
        <button
            onClick={onChange}
            disabled={disabled || loading}
            aria-label={label}
            className={`relative inline-flex h-6 w-11 items-center rounded-full transition-all focus:outline-none ${loading ? 'opacity-50 cursor-wait' : ''} ${disabled ? 'opacity-30 cursor-not-allowed' : 'cursor-pointer'} ${enabled ? activeColor : 'bg-zinc-200'}`}
        >
            <span
                className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${enabled ? 'translate-x-6' : 'translate-x-1'} flex items-center justify-center`}
            >
                {loading && <div className="w-2 h-2 border-2 border-zinc-400 border-t-transparent rounded-full animate-spin" />}
            </span>
        </button>
    );
}

function Stat({ label, value, icon, isPath, color }: any) {
    return (
        <div className="flex flex-col p-2.5 bg-zinc-50 rounded-xl border border-zinc-100/50 hover:bg-zinc-100/50 transition-colors">
            <div className="flex items-center gap-1.5 mb-1.5">
                {icon}
                <span className="text-[10px] font-bold text-zinc-400 uppercase tracking-widest leading-none">
                    {label}
                </span>
            </div>
            <div className="flex items-baseline gap-1">
                <span className={`font-mono text-base font-bold tracking-tight ${color || 'text-zinc-900'} leading-none`}>
                    {value}
                </span>
                {isPath && (
                    <span className="text-[9px] text-zinc-400 font-medium truncate max-w-[80px]">
                        {/* If isPath was meant to show something else, but here we just ensure it doesn't break layout */}
                    </span>
                )}
            </div>
        </div>
    );
}

function MapProgress({ name, size, capacity }: any) {
    const percent = capacity > 0 ? (size / capacity) * 100 : 0;
    const colorClass = percent > 90 ? 'bg-rose-500' : percent > 70 ? 'bg-amber-500' : 'bg-indigo-500';

    return (
        <div className="p-4 bg-zinc-50 rounded-xl border border-zinc-100">
            <div className="flex justify-between items-center mb-2">
                <span className="text-[11px] font-bold text-zinc-600 truncate mr-2 uppercase tracking-tight" title={name}>{name}</span>
                <span className="text-[10px] text-zinc-400 font-mono font-bold">{size}/{capacity}</span>
            </div>
            <div className="w-full h-1.5 bg-zinc-200 rounded-full overflow-hidden">
                <div
                    className={`h-full ${colorClass} transition-all duration-1000 shadow-sm`}
                    style={{ width: `${Math.max(2, percent)}%` }}
                />
            </div>
        </div>
    );
}

function StorageCard({ name, size }: { name: string, size: number }) {
    const capacity = 100 * 1024 * 1024; // 100MB
    const percent = Math.min(100, (size / capacity) * 100);
    const colorClass = size > (capacity * 0.9) ? 'bg-rose-500' : size > (capacity * 0.7) ? 'bg-amber-500' : 'bg-emerald-500';

    return (
        <div className="p-4 bg-zinc-50 rounded-xl border border-zinc-100">
            <div className="flex justify-between items-center mb-2">
                <span className="text-[11px] font-bold text-zinc-600 truncate mr-2 uppercase tracking-tight" title={name}>{name}</span>
                <span className="text-[10px] text-zinc-400 font-mono font-bold">{formatBytes(size)}</span>
            </div>
            <div className="w-full h-1.5 bg-zinc-200 rounded-full overflow-hidden">
                <div
                    className={`h-full ${colorClass} transition-all duration-1000 shadow-sm`}
                    style={{ width: `${Math.max(2, percent)}%` }}
                />
            </div>
        </div>
    );
}

function formatBytes(bytes: number): string {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatUptime(seconds: number): string {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);

    if (days > 0) return `${days}d ${hours}h`;
    if (hours > 0) return `${hours}h ${minutes}m`;
    return `${minutes}m ${seconds % 60}s`;
}

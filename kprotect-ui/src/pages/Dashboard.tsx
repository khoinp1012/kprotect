import { useState, useEffect } from 'react';
import { Activity, Shield, Lock, Server, BarChart3, Fingerprint, Clock, Zap } from 'lucide-react';
import { api, DaemonStatus, EncryptionInfo, SystemInfo } from '../api';

export function Dashboard() {
    const [status, setStatus] = useState<DaemonStatus | null>(null);
    const [encryption, setEncryption] = useState<EncryptionInfo | null>(null);
    const [system, setSystem] = useState<SystemInfo | null>(null);
    const [loading, setLoading] = useState(true);

    const [localUptime, setLocalUptime] = useState(0);

    useEffect(() => {
        loadData();
        const interval = setInterval(loadData, 5000); // Refresh data every 5s

        // Live uptime ticker (every 1s)
        const ticker = setInterval(() => {
            setStatus(currentStatus => {
                if (currentStatus?.ebpf_loaded) {
                    setLocalUptime(prev => prev + 1);
                }
                return currentStatus;
            });
        }, 1000);

        return () => {
            clearInterval(interval);
            clearInterval(ticker);
        };
    }, []);

    async function loadData() {
        try {
            const [s, e, sys] = await Promise.all([
                api.getDaemonStatus(),
                api.getEncryptionInfo(),
                api.getSystemInfo()
            ]);
            setStatus(s);
            // Sync local ticker with server source of truth
            setLocalUptime(s.uptime_seconds);
            setEncryption(e);
            setSystem(sys);
        } catch (err) {
            console.error('Failed to load dashboard data:', err);
        } finally {
            setLoading(false);
        }
    }

    if (loading && !status) {
        return (
            <div className="flex items-center justify-center h-full">
                <Activity className="animate-spin text-indigo-600" size={32} />
            </div>
        );
    }

    return (
        <div className="p-6 space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                {/* Daemon Status Card */}
                <Card
                    title="Daemon Status"
                    icon={<Server className="text-indigo-600" size={20} />}
                    subtitle={status?.ebpf_loaded ? "eBPF Engine Active" : "eBPF Engine Offline"}
                    status={status?.ebpf_loaded ? "success" : "error"}
                >
                    <div className="space-y-3 mt-4">
                        <Stat label="Uptime" value={formatUptime(localUptime)} icon={<Clock size={14} />} />
                        <Stat label="Active Sessions" value={status?.active_connections.toString() || "0"} icon={<Activity size={14} />} />
                        <Stat label="Socket Path" value={status?.socket_path || "/tmp/kprotect.sock"} icon={<Zap size={14} />} isPath />
                    </div>
                </Card>

                {/* Security Status Card */}
                <Card
                    title="Security Governance"
                    icon={<Lock className="text-emerald-600" size={20} />}
                    subtitle={encryption?.enabled ? `AES-256 Protected` : "Encryption Disabled"}
                    status={encryption?.enabled ? "success" : "warning"}
                >
                    <div className="space-y-3 mt-4">
                        <Stat label="Storage Encryption" value={encryption?.enabled ? "Active" : "Disabled"} color={encryption?.enabled ? "text-emerald-600" : "text-amber-600"} />
                        <Stat label="Algorithm" value={encryption?.algorithm || "None"} />
                        <Stat label="Key ID" value={encryption?.key_fingerprint.substring(0, 16) + "..." || "None"} icon={<Fingerprint size={14} />} />
                    </div>
                </Card>

                {/* Activity Overview Card */}
                <Card
                    title="Activity Overview"
                    icon={<BarChart3 className="text-blue-600" size={20} />}
                    subtitle="Real-time Enforcement Stats"
                >
                    <div className="space-y-3 mt-4">
                        <Stat
                            label="Events Verified"
                            value={status?.ebpf_loaded ? (system?.events_verified.toString() || "0") : "—"}
                            color={status?.ebpf_loaded ? "text-emerald-600 font-bold" : "text-zinc-400"}
                        />
                        <Stat
                            label="Events Blocked"
                            value={status?.ebpf_loaded ? (system?.events_blocked.toString() || "0") : "—"}
                            color={status?.ebpf_loaded ? "text-rose-600 font-bold" : "text-zinc-400"}
                        />
                        <Stat
                            label="Active Policies"
                            value={status?.ebpf_loaded ? (system?.authorized_patterns.toString() || "0") : "—"}
                        />
                    </div>
                </Card>
            </div>

            {/* eBPF Maps Section */}
            <div className="bg-white border border-zinc-200 rounded-xl p-6 shadow-sm">
                <div className="flex items-center space-x-3 mb-6">
                    <div className="p-2 bg-indigo-50 rounded-lg">
                        <Shield className="text-indigo-600" size={20} />
                    </div>
                    <div>
                        <h3 className="text-lg font-bold text-zinc-900">Resource Usage</h3>
                        <p className="text-sm text-zinc-500">Memory utilization for Kernel Maps & Daemon Cache</p>
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

function Card({ title, icon, subtitle, children, status }: any) {
    return (
        <div className="bg-white border border-zinc-200 rounded-xl p-5 shadow-sm hover:shadow-md transition-shadow">
            <div className="flex justify-between items-start mb-2">
                <div className="flex items-center space-x-3">
                    <div className="p-2 bg-zinc-50 rounded-lg border border-zinc-100">
                        {icon}
                    </div>
                    <h3 className="font-bold text-zinc-900">{title}</h3>
                </div>
                {status && (
                    <div className={`w-2 h-2 rounded-full mt-2 ${status === 'success' ? 'bg-emerald-500' : status === 'warning' ? 'bg-amber-500' : 'bg-rose-500'} animate-pulse`} />
                )}
            </div>
            <p className="text-xs text-zinc-500 ml-12">{subtitle}</p>
            {children}
        </div>
    );
}

function Stat({ label, value, icon, isPath, color }: any) {
    return (
        <div className="flex justify-between items-center text-sm">
            <span className="text-zinc-500 flex items-center gap-2">
                {icon}
                {label}
            </span>
            <span className={`font-mono font-medium ${isPath ? 'text-[10px] bg-zinc-50 px-1.5 py-0.5 rounded border border-zinc-100' : ''} ${color || 'text-zinc-900'}`}>
                {value}
            </span>
        </div>
    );
}

function MapProgress({ name, size, capacity }: any) {
    const percent = capacity > 0 ? (size / capacity) * 100 : 0;
    const colorClass = percent > 90 ? 'bg-rose-500' : percent > 70 ? 'bg-amber-500' : 'bg-indigo-500';

    return (
        <div className="p-4 bg-zinc-50 rounded-lg border border-zinc-100">
            <div className="flex justify-between items-center mb-2">
                <span className="text-xs font-bold text-zinc-600 truncate mr-2" title={name}>{name}</span>
                <span className="text-[10px] text-zinc-400 font-mono">{size}/{capacity}</span>
            </div>
            <div className="w-full h-1.5 bg-zinc-200 rounded-full overflow-hidden">
                <div
                    className={`h-full ${colorClass} transition-all duration-1000`}
                    style={{ width: `${Math.max(2, percent)}%` }}
                />
            </div>
        </div>
    );
}

function StorageCard({ name, size }: { name: string, size: number }) {
    // Show progress relative to 100MB soft limit for visual consistency
    const capacity = 100 * 1024 * 1024; // 100MB
    const percent = Math.min(100, (size / capacity) * 100);
    const colorClass = size > (capacity * 0.9) ? 'bg-rose-500' : size > (capacity * 0.7) ? 'bg-amber-500' : 'bg-emerald-500';

    return (
        <div className="p-4 bg-zinc-50 rounded-lg border border-zinc-100">
            <div className="flex justify-between items-center mb-2">
                <span className="text-xs font-bold text-zinc-600 truncate mr-2" title={name}>{name}</span>
                <span className="text-[10px] text-zinc-400 font-mono">{formatBytes(size)}</span>
            </div>
            <div className="w-full h-1.5 bg-zinc-200 rounded-full overflow-hidden">
                <div
                    className={`h-full ${colorClass} transition-all duration-1000`}
                    style={{ width: `${Math.max(2, percent)}%` }}
                />
            </div>
        </div>
    );
}

function formatUptime(seconds: number): string {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);

    if (days > 0) return `${days}d ${hours}h`;
    if (hours > 0) return `${hours}h ${minutes}m`;
    return `${minutes}m ${seconds % 60}s`;
}

function formatBytes(bytes: number): string {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

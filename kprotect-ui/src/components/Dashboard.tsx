import { useState, useEffect } from 'react';
import { Shield, Lock, Server, Database, Clock } from 'lucide-react';
import { useGlobal } from '../context/GlobalContext';
import { api, DaemonStatus, EncryptionInfo, SystemInfo } from '../api';

export function Dashboard() {
    const { isRootActive } = useGlobal();
    const [daemonStatus, setDaemonStatus] = useState<DaemonStatus | null>(null);
    const [encryptionInfo, setEncryptionInfo] = useState<EncryptionInfo | null>(null);
    const [systemInfo, setSystemInfo] = useState<SystemInfo | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    const fetchData = async () => {
        try {
            setLoading(true);
            const [status, encryption, system] = await Promise.all([
                api.getDaemonStatus(),
                api.getEncryptionInfo(),
                api.getSystemInfo(),
            ]);
            setDaemonStatus(status);
            setEncryptionInfo(encryption);
            setSystemInfo(system);
            setError(null);
        } catch (e: any) {
            setError(e.toString());
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchData();
        // Refresh every 10 seconds
        const interval = setInterval(fetchData, 10000);
        return () => clearInterval(interval);
    }, [isRootActive]);

    if (error) {
        return (
            <div className="p-6">
                <div className="bg-rose-50 border border-rose-200 rounded-lg p-4 text-rose-700">
                    <p className="font-semibold">Failed to load system status</p>
                    <p className="text-sm mt-1">{error}</p>
                    <button
                        onClick={fetchData}
                        className="mt-3 px-4 py-2 bg-rose-600 text-white rounded-md hover:bg-rose-700 text-sm"
                    >
                        Retry
                    </button>
                </div>
            </div>
        );
    }

    if (loading || !daemonStatus || !encryptionInfo || !systemInfo) {
        return (
            <div className="p-6 flex items-center justify-center">
                <div className="text-zinc-500">Loading system status...</div>
            </div>
        );
    }

    const uptimeFormatted = formatUptime(daemonStatus.uptime_seconds);

    return (
        <div className="space-y-6">
            {/* Critical Status Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {/* Daemon Health */}
                <StatusCard
                    title="Daemon Health"
                    icon={<Server className="text-emerald-600" size={20} />}
                    status="healthy"
                >
                    <div className="mt-3 space-y-2 text-sm">
                        <div className="flex justify-between">
                            <span className="text-zinc-500">Uptime:</span>
                            <span className="font-mono text-zinc-900">{uptimeFormatted}</span>
                        </div>
                        <div className="flex justify-between">
                            <span className="text-zinc-500">Connections:</span>
                            <span className="font-mono text-zinc-900">{daemonStatus.active_connections}</span>
                        </div>
                    </div>
                </StatusCard>

                {/* Encryption Status */}
                <StatusCard
                    title="Encryption"
                    icon={<Lock className="text-indigo-600" size={20} />}
                    status="secure"
                >
                    <div className="mt-3 space-y-2 text-sm">
                        <div className="flex justify-between">
                            <span className="text-zinc-500">Algorithm:</span>
                            <span className="font-semibold text-indigo-600">{encryptionInfo.algorithm}</span>
                        </div>
                        <div className="flex justify-between items-center">
                            <span className="text-zinc-500">Key:</span>
                            <code className="text-[10px] bg-zinc-100 px-2 py-0.5 rounded text-zinc-700">
                                {encryptionInfo.key_fingerprint}
                            </code>
                        </div>
                        <div className="flex justify-between">
                            <span className="text-zinc-500">Files:</span>
                            <span className="font-mono text-zinc-900">{encryptionInfo.policy_files.length} encrypted</span>
                        </div>
                    </div>
                </StatusCard>

                {/* Socket Info */}
                <StatusCard
                    title="Connection"
                    icon={<Database className="text-violet-600" size={20} />}
                    status="connected"
                >
                    <div className="mt-3 space-y-2 text-sm">
                        <div className="flex justify-between">
                            <span className="text-zinc-500">Socket:</span>
                            <code className="text-[10px] bg-zinc-100 px-2 py-0.5 rounded text-zinc-700 truncate max-w-[150px]" title={daemonStatus.socket_path}>
                                {daemonStatus.socket_path.split('/').pop()}
                            </code>
                        </div>
                        <div className="flex justify-between">
                            <span className="text-zinc-500">Protocol:</span>
                            <span className="font-semibold text-violet-600">v1.0</span>
                        </div>
                    </div>
                </StatusCard>
            </div>

            {/* Policy Statistics */}
            <div className="bg-white border border-zinc-200 rounded-lg p-6 shadow-sm">
                <h3 className="text-sm font-semibold text-zinc-900 mb-4 flex items-center">
                    <Shield className="mr-2 text-zinc-600" size={18} />
                    Policy Configuration
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <PolicyStat
                        label="Authorized Patterns"
                        value={systemInfo.authorized_patterns}
                        color="emerald"
                    />
                    <PolicyStat
                        label="Red Zones"
                        value={systemInfo.red_zones}
                        color="rose"
                    />
                    <PolicyStat
                        label="Enrichment Rules"
                        value={systemInfo.enrichment_patterns}
                        color="indigo"
                    />
                </div>
            </div>


            {/* Policy Files */}
            <div className="bg-white border border-zinc-200 rounded-lg p-6 shadow-sm">
                <h3 className="text-sm font-semibold text-zinc-900 mb-4 flex items-center">
                    <Clock className="mr-2 text-zinc-600" size={18} />
                    Encrypted Policy Files
                </h3>
                <div className="space-y-2">
                    {encryptionInfo.policy_files.map((file, idx) => (
                        <div key={idx} className="flex justify-between items-center py-2 border-b border-zinc-100 last:border-0">
                            <span className="text-sm font-mono text-zinc-600 truncate">{file.path.split('/').pop()}</span>
                            <span className="text-xs text-zinc-400">{formatTimestamp(file.last_modified)}</span>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
}

function StatusCard({ title, icon, status, children }: {
    title: string;
    icon: React.ReactNode;
    status: 'healthy' | 'secure' | 'connected';
    children: React.ReactNode;
}) {
    const borderColors = {
        healthy: 'border-emerald-100',
        secure: 'border-indigo-100',
        connected: 'border-violet-100',
    };

    return (
        <div className={`bg-white border ${borderColors[status]} rounded-lg p-5 shadow-sm`}>
            <div className="flex justify-between items-start mb-2">
                <h3 className="text-xs font-semibold uppercase tracking-wide text-zinc-500">{title}</h3>
                <div className="p-2 bg-zinc-50 rounded-md">
                    {icon}
                </div>
            </div>
            {children}
        </div>
    );
}

function PolicyStat({ label, value, color }: { label: string; value: number; color: string }) {
    const colors = {
        emerald: 'text-emerald-600 bg-emerald-5',
        rose: 'text-rose-600 bg-rose-50',
        indigo: 'text-indigo-600 bg-indigo-50',
    };

    return (
        <div className="text-center">
            <div className={`text-3xl font-bold ${colors[color as keyof typeof colors]}`}>{value}</div>
            <div className="text-xs text-zinc-500 mt-1 uppercase tracking-wide">{label}</div>
        </div>
    );
}


function formatUptime(seconds: number): string {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);

    if (days > 0) return `${days}d ${hours}h`;
    if (hours > 0) return `${hours}h ${minutes}m`;
    return `${minutes}m`;
}

function formatTimestamp(unix: number): string {
    const date = new Date(unix * 1000);
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const minutes = Math.floor(diff / 60000);

    if (minutes < 1) return 'just now';
    if (minutes < 60) return `${minutes}m ago`;
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours}h ago`;
    return date.toLocaleDateString();
}

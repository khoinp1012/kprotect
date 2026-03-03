import { createContext, useContext, useState, useEffect, ReactNode, useRef } from 'react';
import { api } from '../api';
import { listen } from '@tauri-apps/api/event';
import { toast } from 'sonner';
import { Event, AuditLog, AuthorizedPattern } from '../types';
import { isPermissionGranted, requestPermission, sendNotification } from '@tauri-apps/plugin-notification';

interface GlobalState {
    events: Event[];
    auditLogs: AuditLog[];
    allowlistCount: number;
    isRootActive: boolean;
    isConnected: boolean;
    allowlist: AuthorizedPattern[];
    refreshAllowlist: () => void;
    checkRootStatus: () => Promise<void>;
    elevationEvents: Event[];
    clearEvents: () => void;
    clearElevationEvents: () => void;
    loadMoreEvents: () => Promise<void>;
    loadMoreAuditLogs: () => Promise<void>;
    refreshAuditLogs: () => Promise<void>;
    blockedAlertsEnabled: boolean;
    setBlockedAlertsEnabled: (enabled: boolean) => void;
    authorizedAlertsEnabled: boolean;
    setAuthorizedAlertsEnabled: (enabled: boolean) => void;
    sudoBlockedAlertsEnabled: boolean;
    setSudoBlockedAlertsEnabled: (enabled: boolean) => void;
    sudoAuthorizedAlertsEnabled: boolean;
    setSudoAuthorizedAlertsEnabled: (enabled: boolean) => void;
    compressionEnabled: boolean;
    setCompressionEnabled: (enabled: boolean) => void;
}

export const GlobalContext = createContext<GlobalState | undefined>(undefined);

// Utility Helpers (Pure functions outside to avoid stale closures/hoisting issues)
export const mapRawEventToUI = (raw: any): Event => {
    const statusStr = (raw.status || "").trim();
    let status: 'Verified' | 'Blocked' | 'Birth' | 'Exit' | 'Elevation' | 'Blocked Elevation' | 'Standard Elevation' | 'Sudo Launch (Authored)' | 'Sudo Launch (Cached)' | 'Unknown' = 'Unknown';

    if (statusStr === 'Verified') status = 'Verified';
    else if (statusStr === 'Blocked') status = 'Blocked';
    else if (statusStr === 'Birth') status = 'Birth';
    else if (statusStr === 'Exit') status = 'Exit';
    else if (statusStr === 'Elevation') status = 'Elevation';
    else if (statusStr === 'Blocked Elevation') status = 'Blocked Elevation';
    else if (statusStr === 'Sudo Launch (Authored)') status = 'Sudo Launch (Authored)';
    else if (statusStr === 'Sudo Launch (Cached)') status = 'Sudo Launch (Cached)';
    else if (statusStr === 'Standard Elevation') status = 'Standard Elevation';
    else {
        console.error(`Unknown event status received: "${statusStr}"`, raw);
    }

    const eventId = raw.id || `${raw.timestamp || Date.now()}_${raw.pid || 0}_${Math.random().toString(36).substring(2, 7)}`;

    return {
        id: eventId,
        timestamp: typeof raw.timestamp === 'number' ? new Date(raw.timestamp * 1000).toISOString() : (raw.timestamp || new Date().toISOString()),
        status,
        pid: raw.pid || 0,
        chain: Array.isArray(raw.chain) ? raw.chain : (raw.comm ? [raw.comm] : []),
        path: raw.target || raw.path || (Array.isArray(raw.chain) && raw.chain.length > 0 ? raw.chain[raw.chain.length - 1] : (raw.comm || 'unknown')),
        complete: !!raw.complete,
        signature: raw.signature,
        comm: raw.comm || (Array.isArray(raw.chain) && raw.chain.length > 0 ? raw.chain[raw.chain.length - 1] : 'unknown')
    };
};

export const compressEvents = (rawList: Event[]): Event[] => {
    if (rawList.length === 0) return [];

    // Grouping by "Identity": Status + Path + Chain
    const groups = new Map<string, Event>();

    // Keep track of order of appearance for sorting later
    const appearanceOrder: string[] = [];

    rawList.forEach(event => {
        const identity = `${event.status}|${event.path}|${JSON.stringify(event.chain)}`;

        if (groups.has(identity)) {
            const existing = groups.get(identity)!;
            existing.count = (existing.count || 1) + (event.count || 1);
            // Keep the latest timestamp
            if (new Date(event.timestamp) > new Date(existing.timestamp)) {
                existing.timestamp = event.timestamp;
                existing.pid = event.pid;
            }
        } else {
            groups.set(identity, { ...event, count: event.count || 1 });
            appearanceOrder.push(identity);
        }
    });

    // Convert Map back to array, sorted by most recent timestamp
    const result = Array.from(groups.values()).sort(
        (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
    );

    console.log(`[Compress] Global Summary: ${rawList.length} events -> ${result.length} unique groups`);
    return result;
};

// Recompress is now simpler as compressEvents handles global grouping
const recompressGroups = (groups: Event[]): Event[] => {
    return compressEvents(groups);
};

export function GlobalProvider({ children }: { children: ReactNode }) {
    const [events, setEvents] = useState<Event[]>([]);
    const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
    const [elevationEvents, setElevationEvents] = useState<Event[]>([]);
    const processedEventIds = useRef<Set<number | string>>(new Set());
    const [allowlistCount, setAllowlistCount] = useState(0);
    const [isRootActive, setIsRootActive] = useState(false);
    const [isConnected, setIsConnected] = useState(false);
    const [allowlist, setAllowlist] = useState<AuthorizedPattern[]>([]);

    const [blockedAlertsEnabled, _setBlockedAlertsEnabled] = useState(() => {
        const saved = localStorage.getItem('blockedAlertsEnabled');
        return saved !== null ? saved === 'true' : true;
    });
    const [authorizedAlertsEnabled, _setAuthorizedAlertsEnabled] = useState(() => {
        const saved = localStorage.getItem('authorizedAlertsEnabled');
        return saved !== null ? saved === 'true' : false;
    });
    const [sudoBlockedAlertsEnabled, _setSudoBlockedAlertsEnabled] = useState(() => {
        const saved = localStorage.getItem('sudoBlockedAlertsEnabled');
        return saved !== null ? saved === 'true' : true;
    });
    const [sudoAuthorizedAlertsEnabled, _setSudoAuthorizedAlertsEnabled] = useState(() => {
        const saved = localStorage.getItem('sudoAuthorizedAlertsEnabled');
        return saved !== null ? saved === 'true' : true;
    });
    const [compressionEnabled, _setCompressionEnabled] = useState(() => {
        const saved = localStorage.getItem('compressionEnabled');
        return saved !== null ? saved === 'true' : true;
    });

    const blockedAlertsEnabledRef = useRef(blockedAlertsEnabled);
    const authorizedAlertsEnabledRef = useRef(authorizedAlertsEnabled);
    const sudoBlockedAlertsEnabledRef = useRef(sudoBlockedAlertsEnabled);
    const sudoAuthorizedAlertsEnabledRef = useRef(sudoAuthorizedAlertsEnabled);
    const compressionEnabledRef = useRef(compressionEnabled);

    const setBlockedAlertsEnabled = (enabled: boolean) => {
        _setBlockedAlertsEnabled(enabled);
        blockedAlertsEnabledRef.current = enabled;
        localStorage.setItem('blockedAlertsEnabled', enabled.toString());
    };

    const setAuthorizedAlertsEnabled = (enabled: boolean) => {
        _setAuthorizedAlertsEnabled(enabled);
        authorizedAlertsEnabledRef.current = enabled;
        localStorage.setItem('authorizedAlertsEnabled', enabled.toString());
    };

    const setSudoBlockedAlertsEnabled = (enabled: boolean) => {
        _setSudoBlockedAlertsEnabled(enabled);
        sudoBlockedAlertsEnabledRef.current = enabled;
        localStorage.setItem('sudoBlockedAlertsEnabled', enabled.toString());
    };

    const setSudoAuthorizedAlertsEnabled = (enabled: boolean) => {
        _setSudoAuthorizedAlertsEnabled(enabled);
        sudoAuthorizedAlertsEnabledRef.current = enabled;
        localStorage.setItem('sudoAuthorizedAlertsEnabled', enabled.toString());
    };

    const setCompressionEnabled = (enabled: boolean) => {
        console.log('[GlobalContext] setCompressionEnabled called with:', enabled);
        console.log('[GlobalContext] Previous compressionEnabled:', compressionEnabled);
        _setCompressionEnabled(enabled);
        compressionEnabledRef.current = enabled;
        localStorage.setItem('compressionEnabled', enabled.toString());
        console.log('[GlobalContext] Updated compressionEnabled to:', enabled);
        console.log('[GlobalContext] localStorage updated');
    };

    useEffect(() => {
        blockedAlertsEnabledRef.current = blockedAlertsEnabled;
        authorizedAlertsEnabledRef.current = authorizedAlertsEnabled;
        sudoBlockedAlertsEnabledRef.current = sudoBlockedAlertsEnabled;
        sudoAuthorizedAlertsEnabledRef.current = sudoAuthorizedAlertsEnabled;
        compressionEnabledRef.current = compressionEnabled;
    }, [blockedAlertsEnabled, authorizedAlertsEnabled, sudoBlockedAlertsEnabled, sudoAuthorizedAlertsEnabled, compressionEnabled]);

    const eventBuffer = useRef<Event[]>([]);
    const elevationBuffer = useRef<Event[]>([]);
    const rawEventCount = useRef<number>(0);

    // Recompress state when toggle changes
    useEffect(() => {
        if (compressionEnabled) {
            setEvents(prev => recompressGroups(compressEvents(prev)));
            setElevationEvents(prev => recompressGroups(compressEvents(prev)));
        } else {
            const reloadRawEvents = async () => {
                try {
                    const CHUNK_SIZE = 200;
                    const rawEvents = await api.getSecurityEvents(CHUNK_SIZE, 0);

                    if (Array.isArray(rawEvents)) {
                        rawEventCount.current = rawEvents.length;
                        const allMapped = rawEvents.map(mapRawEventToUI);

                        const sudoMapped = allMapped.filter(e => e.status === 'Elevation' || e.status === 'Blocked Elevation' || e.status === 'Standard Elevation' || e.status.startsWith('Sudo Launch'));
                        const fileMapped = allMapped.filter(e => e.status !== 'Birth' && e.status !== 'Elevation' && e.status !== 'Blocked Elevation' && e.status !== 'Standard Elevation' && !e.status.startsWith('Sudo Launch'));

                        setEvents(fileMapped);
                        setElevationEvents(sudoMapped);
                    }
                } catch (e) {
                    console.error('[CompressionEffect] Failed to reload raw events:', e);
                }
            };
            reloadRawEvents();
        }
    }, [compressionEnabled]);

    const refreshAllowlist = async () => {
        try {
            const patterns = await api.getAllowlist();
            if (Array.isArray(patterns)) {
                setAllowlistCount(patterns.length);
                setAllowlist(patterns);
            }
        } catch (e) {
            console.error(e);
        }
    };

    const checkRootStatus = async () => {
        try {
            const active = await api.checkRootStatus();
            setIsRootActive(active);
        } catch (e) {
            console.error(e);
        }
    };

    const clearEvents = () => {
        setEvents([]);
        rawEventCount.current = 0;
    };

    const clearElevationEvents = () => {
        setElevationEvents([]);
    };

    const checkNotificationPermission = async () => {
        let permission = await isPermissionGranted();
        if (!permission) {
            const permission_request = await requestPermission();
            permission = permission_request === 'granted';
        }
    };

    const setupEventListener = async () => {
        try {
            processedEventIds.current.clear();
            const unlisten = await listen<any>("event", async (payload) => {
                setIsConnected(true);
                const raw = payload.payload;
                const newEvent = mapRawEventToUI(raw);

                if (processedEventIds.current.has(newEvent.id)) return;
                processedEventIds.current.add(newEvent.id);

                const shouldNotify = (newEvent.status === 'Blocked' && blockedAlertsEnabledRef.current) ||
                    (newEvent.status === 'Verified' && authorizedAlertsEnabledRef.current) ||
                    (newEvent.status === 'Blocked Elevation' && sudoBlockedAlertsEnabledRef.current) ||
                    (newEvent.status === 'Elevation' && sudoAuthorizedAlertsEnabledRef.current);

                if (shouldNotify) {
                    try {
                        const isSudo = newEvent.status.includes('Elevation');
                        await sendNotification({
                            title: isSudo ? `Sudo Alert: ${newEvent.status}` : `Security Alert: ${newEvent.status}`,
                            body: isSudo
                                ? `Process ${newEvent.pid} ${newEvent.status.toLowerCase()} access to Sudo.`
                                : `Process ${newEvent.pid} was ${newEvent.status.toLowerCase()} from accessing ${newEvent.path}.`,
                        });
                    } catch (error) {
                        console.error('[Notification] Failed:', error);
                    }
                }

                if (newEvent.status === 'Blocked' && blockedAlertsEnabledRef.current) {
                    toast.error(`Security Alert: ${newEvent.status}`, {
                        description: `${newEvent.path} access blocked`,
                        duration: 5000,
                    });
                }

                if (newEvent.status === 'Blocked Elevation' && sudoBlockedAlertsEnabledRef.current) {
                    toast.error(`Sudo Blocked`, {
                        description: `Elevation request denied for PID ${newEvent.pid}`,
                        duration: 5000,
                    });
                }

                if (newEvent.status === 'Elevation' && sudoAuthorizedAlertsEnabledRef.current) {
                    toast.success(`Sudo Verified`, {
                        description: `Elevation request granted for PID ${newEvent.pid}`,
                        duration: 3000,
                    });
                }

                if (newEvent.status === 'Birth') return;

                if (newEvent.status === 'Elevation' || newEvent.status === 'Blocked Elevation' || newEvent.status === 'Standard Elevation' || newEvent.status.startsWith('Sudo Launch')) {
                    elevationBuffer.current.push(newEvent);
                } else {
                    eventBuffer.current.push(newEvent);
                }
            });
            return unlisten;
        } catch (e) {
            console.error("Failed to setup event listener", e);
            setIsConnected(false);
        }
    };

    const loadInitialData = async () => {
        try {
            const CHUNK_SIZE = 200;
            const rawEvents = await api.getSecurityEvents(CHUNK_SIZE, 0);

            if (Array.isArray(rawEvents)) {
                rawEventCount.current = rawEvents.length;
                const allMapped = rawEvents.map(mapRawEventToUI);

                const fileMapped = allMapped.filter(e => e.status !== 'Birth' && e.status !== 'Elevation' && e.status !== 'Blocked Elevation' && e.status !== 'Standard Elevation' && !e.status.startsWith('Sudo Launch'));
                const sudoMapped = allMapped.filter(e => e.status === 'Elevation' || e.status === 'Blocked Elevation' || e.status === 'Standard Elevation' || e.status.startsWith('Sudo Launch'));

                if (!compressionEnabledRef.current) {
                    setEvents(fileMapped);
                    setElevationEvents(sudoMapped.slice(0, 500));
                } else {
                    setEvents(recompressGroups(compressEvents(fileMapped)));
                    setElevationEvents(recompressGroups(compressEvents(sudoMapped)).slice(0, 500));
                }
            }

            const rawAudit = await api.getAuditLogs(100, 0);
            if (Array.isArray(rawAudit)) {
                setAuditLogs(rawAudit);
            }
        } catch (e) {
            console.error("Failed to load initial data:", e);
        }
    };

    const loadMoreEvents = async () => {
        try {
            const offset = rawEventCount.current;
            const count = 200;
            const rawEvents = await api.getSecurityEvents(count, offset);

            if (Array.isArray(rawEvents)) {
                const mapped = rawEvents
                    .map(mapRawEventToUI)
                    .filter(e => e.status !== 'Birth' && e.status !== 'Elevation' && e.status !== 'Blocked Elevation' && e.status !== 'Standard Elevation' && !e.status.startsWith('Sudo Launch'));
                rawEventCount.current += rawEvents.length;

                setEvents(prev => {
                    if (!compressionEnabledRef.current) {
                        return [...prev, ...mapped];
                    }
                    const compressedChunk = compressEvents(mapped);
                    if (prev.length === 0) return compressedChunk;
                    if (compressedChunk.length === 0) return prev;

                    const lastGroup = prev[prev.length - 1];
                    const firstNewGroup = compressedChunk[0];

                    const canMerge = lastGroup.path === firstNewGroup.path &&
                        lastGroup.status === firstNewGroup.status &&
                        JSON.stringify(lastGroup.chain) === JSON.stringify(firstNewGroup.chain);

                    if (canMerge) {
                        const merged = {
                            ...lastGroup,
                            count: (lastGroup.count || 1) + (firstNewGroup.count || 1),
                            timestamp: firstNewGroup.timestamp,
                            pid: firstNewGroup.pid
                        };
                        return [...prev.slice(0, -1), merged, ...compressedChunk.slice(1)];
                    } else {
                        return recompressGroups([...prev, ...compressedChunk]);
                    }
                });
            }
        } catch (e) {
            console.error("Failed to load more events:", e);
        }
    };

    const loadMoreAuditLogs = async () => {
        try {
            const offset = auditLogs.length;
            const count = 50;
            const rawAudit = await api.getAuditLogs(count, offset);
            if (Array.isArray(rawAudit)) {
                setAuditLogs(prev => {
                    const existingKeys = new Set(prev.map(l => `${l.timestamp}-${l.action}-${l.username}`));
                    const next = [...prev];
                    rawAudit.forEach(l => {
                        const key = `${l.timestamp}-${l.action}-${l.username}`;
                        if (!existingKeys.has(key)) next.push(l);
                    });
                    return next.sort((a, b) => b.timestamp - a.timestamp).slice(0, 2000);
                });
            }
        } catch (e) {
            console.error("Failed to load more audit logs:", e);
        }
    };

    const refreshAuditLogs = async () => {
        try {
            const rawAudit = await api.getAuditLogs(100, 0);
            if (Array.isArray(rawAudit)) setAuditLogs(rawAudit);
        } catch (e) {
            console.error("Failed to refresh audit logs:", e);
        }
    };

    // Main Lifecycle
    useEffect(() => {
        refreshAllowlist();
        checkRootStatus();
        setupEventListener();
        loadInitialData();
        checkNotificationPermission();

        const flushInterval = setInterval(() => {
            if (eventBuffer.current.length > 0) {
                const batch = [...eventBuffer.current];
                eventBuffer.current = [];

                setEvents(prev => {
                    const mapped = batch.filter(e => e.status !== 'Birth' && e.status !== 'Elevation' && e.status !== 'Blocked Elevation' && e.status !== 'Standard Elevation' && !e.status.startsWith('Sudo Launch'));
                    if (!compressionEnabledRef.current) return [...mapped, ...prev].slice(0, 1000);

                    const compressedBatch = compressEvents(mapped);
                    return recompressGroups([...compressedBatch, ...prev]).slice(0, 1000);
                });
            }

            if (elevationBuffer.current.length > 0) {
                const batch = [...elevationBuffer.current];
                elevationBuffer.current = [];
                setElevationEvents(prev => {
                    if (!compressionEnabledRef.current) return [...batch, ...prev].slice(0, 500);
                    const compressedBatch = compressEvents(batch);
                    return recompressGroups([...compressedBatch, ...prev]).slice(0, 500);
                });
            }
        }, 500);

        const healthCheckInterval = setInterval(async () => {
            try {
                await api.checkRootStatus();
                setIsConnected(true);
            } catch (e) {
                setIsConnected(false);
            }
        }, 3000);

        return () => {
            clearInterval(flushInterval);
            clearInterval(healthCheckInterval);
        };
    }, []);

    return (
        <GlobalContext.Provider value={{
            events,
            elevationEvents,
            auditLogs,
            allowlistCount,
            isRootActive,
            isConnected,
            refreshAllowlist,
            checkRootStatus,
            clearEvents,
            clearElevationEvents,
            loadMoreEvents,
            loadMoreAuditLogs,
            refreshAuditLogs,
            blockedAlertsEnabled,
            setBlockedAlertsEnabled,
            authorizedAlertsEnabled,
            setAuthorizedAlertsEnabled,
            sudoBlockedAlertsEnabled,
            setSudoBlockedAlertsEnabled,
            sudoAuthorizedAlertsEnabled,
            setSudoAuthorizedAlertsEnabled,
            compressionEnabled,
            setCompressionEnabled,
            allowlist
        }}>
            {children}
        </GlobalContext.Provider>
    );
}

export function useGlobal() {
    const context = useContext(GlobalContext);
    if (!context) throw new Error("useGlobal must be used within GlobalProvider");
    return context;
}

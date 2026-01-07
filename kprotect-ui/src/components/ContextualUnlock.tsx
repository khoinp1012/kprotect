import { Zap } from 'lucide-react';
import { api } from '../api';
import { useGlobal } from '../context/GlobalContext';
import { toast } from 'sonner';

interface ContextualUnlockProps {
    message?: string;
    description?: string;
    actionLabel?: string;
}

export function ContextualUnlock({
    message = "Restricted Access",
    description = "You need an active root session to perform this action.",
    actionLabel = "Unlock to Modify"
}: ContextualUnlockProps) {
    const { checkRootStatus, refreshAllowlist } = useGlobal();

    const handleTriggerRoot = async () => {
        try {
            const promise = api.startRootSession();
            toast.promise(promise, {
                loading: 'Authenticating...',
                success: 'Root Session Started',
                error: (err) => `Failed: ${err}`
            });
            await promise;

            // Poll for status
            let attempts = 0;
            while (attempts < 300) {
                await new Promise(r => setTimeout(r, 200));
                const active = await api.checkRootStatus();
                if (active) {
                    await checkRootStatus();
                    await refreshAllowlist();
                    return;
                }
                attempts++;
            }
        } catch (e: any) {
            // Toast handled above
        }
    };

    return (
        <div className="bg-amber-50 border border-amber-200 rounded-2xl p-6 flex flex-col sm:flex-row items-center justify-between gap-4 animate-in fade-in slide-in-from-top-2">
            <div className="flex items-center space-x-4 text-center sm:text-left">
                <div className="p-3 bg-amber-100 rounded-xl text-amber-600">
                    <Zap size={24} fill="currentColor" />
                </div>
                <div>
                    <h4 className="font-bold text-amber-900">{message}</h4>
                    <p className="text-sm text-amber-700 font-medium">{description}</p>
                </div>
            </div>
            <button
                onClick={handleTriggerRoot}
                className="w-full sm:w-auto flex items-center justify-center px-6 py-3 bg-amber-600 hover:bg-amber-700 text-white rounded-xl font-bold text-sm transition-all shadow-lg shadow-amber-200 active:scale-95 whitespace-nowrap"
            >
                <Zap size={16} className="mr-2" fill="currentColor" />
                {actionLabel}
            </button>
        </div>
    );
}

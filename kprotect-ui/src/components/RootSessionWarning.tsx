import { AlertTriangle } from 'lucide-react';

interface RootSessionWarningProps {
    message?: string;
    description?: string;
}

export function RootSessionWarning({
    message = "Root Session Required",
    description = "This action requires an active root session. Please authenticate via the toolbar button above to continue."
}: RootSessionWarningProps) {
    return (
        <div className="p-4 bg-amber-50 border border-amber-200 rounded-2xl flex items-start space-x-4 animate-in fade-in slide-in-from-top-2 duration-300 shadow-sm">
            <div className="p-2 bg-amber-100 rounded-xl">
                <AlertTriangle className="text-amber-600" size={20} />
            </div>
            <div>
                <p className="text-sm font-bold text-amber-900 uppercase tracking-tight">{message}</p>
                <p className="text-xs text-amber-700/80 mt-1 font-medium leading-relaxed">
                    {description}
                </p>
            </div>
        </div>
    );
}

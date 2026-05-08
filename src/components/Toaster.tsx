import { useEffect, useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { CheckCircle2, XCircle, Loader2, Info } from 'lucide-react';
import { toast, Toast } from '../toast';
import { cn } from '../utils';

export function Toaster() {
  const [toasts, setToasts] = useState<Toast[]>([]);

  useEffect(() => {
    return toast.subscribe(setToasts);
  }, []);

  return (
    <div className="fixed bottom-0 right-0 z-[100] p-6 space-y-3 pointer-events-none w-full max-w-sm flex flex-col items-end">
      <AnimatePresence mode="popLayout">
        {toasts.map((t) => (
          <motion.div
            key={t.id}
            layout
            initial={{ opacity: 0, y: 50, scale: 0.9 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, scale: 0.9, transition: { duration: 0.2 } }}
            className={cn(
              "pointer-events-auto flex items-center gap-3 px-4 py-3 rounded-2xl shadow-2xl backdrop-blur-xl border border-white/10 text-sm font-medium w-full overflow-hidden relative",
              t.type === 'success' && "bg-brand-emerald/10 border-brand-emerald/20 text-brand-emerald",
              t.type === 'error' && "bg-red-500/10 border-red-500/20 text-red-400",
              t.type === 'loading' && "bg-brand-cyan/10 border-brand-cyan/20 text-brand-cyan",
              t.type === 'info' && "bg-white/10 text-white"
            )}
          >
            {t.type === 'success' && <CheckCircle2 className="w-5 h-5 shrink-0" />}
            {t.type === 'error' && <XCircle className="w-5 h-5 shrink-0" />}
            {t.type === 'loading' && <Loader2 className="w-5 h-5 animate-spin shrink-0" />}
            {t.type === 'info' && <Info className="w-5 h-5 shrink-0" />}
            
            <span className="flex-1 drop-shadow-md text-xs leading-relaxed">{t.message}</span>
            
            {t.type !== 'loading' && (
              <button 
                onClick={() => toast.dismiss(t.id)} 
                className="ml-2 opacity-50 hover:opacity-100 transition-opacity p-1"
              >
                <XCircle className="w-4 h-4" />
              </button>
            )}
            
            {/* Subtle glow effect */}
            <div className={cn(
              "absolute inset-0 opacity-10 pointer-events-none mix-blend-overlay",
              t.type === 'success' ? "bg-gradient-to-r from-brand-emerald to-transparent" :
              t.type === 'error' ? "bg-gradient-to-r from-red-500 to-transparent" :
              t.type === 'loading' ? "bg-gradient-to-r from-brand-cyan to-transparent" : ""
            )} />
          </motion.div>
        ))}
      </AnimatePresence>
    </div>
  );
}

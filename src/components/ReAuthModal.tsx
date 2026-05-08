import { motion, AnimatePresence } from "framer-motion";
import { Lock } from "lucide-react";
import { AuthTarget } from "../types";

interface ReAuthModalProps {
  authTarget: AuthTarget;
  authInput: string;
  onAuthInputChange: (value: string) => void;
  onVerify: () => void;
  onCancel: () => void;
}

export function ReAuthModal({
  authTarget,
  authInput,
  onAuthInputChange,
  onVerify,
  onCancel,
}: ReAuthModalProps) {
  return (
    <AnimatePresence>
      {authTarget && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/80 backdrop-blur-md">
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.95 }}
            className="w-full max-w-sm bg-black border border-brand-cyan/30 rounded-[32px] p-8 shadow-2xl"
          >
            <div className="flex flex-col items-center text-center">
              <div className="w-16 h-16 rounded-2xl bg-brand-cyan/10 flex items-center justify-center border border-brand-cyan/20 mb-6 text-brand-cyan shadow-inner">
                <Lock className="w-8 h-8" />
              </div>
              <h2 className="text-xl font-bold mb-2">Sección Protegida</h2>
              <p className="text-xs text-white/40 mb-6">Confirma tu Contraseña Maestra</p>

              <input
                type="password"
                value={authInput}
                onChange={(e) => onAuthInputChange(e.target.value)}
                placeholder="Contraseña..."
                autoFocus
                className="w-full bg-[#111] border border-white/10 rounded-xl px-4 py-3 text-white placeholder-white/30 focus:outline-none focus:border-brand-cyan/50 focus:ring-1 focus:ring-brand-cyan/50 text-center mb-4"
                onKeyDown={(e) => {
                  if (e.key === 'Enter') onVerify();
                  if (e.key === 'Escape') onCancel();
                }}
              />
              <div className="flex gap-3 w-full">
                <button
                  onClick={onCancel}
                  className="flex-1 py-3 bg-white/5 hover:bg-white/10 text-white rounded-xl font-bold uppercase tracking-widest text-[10px] transition-colors"
                >
                  Cancelar
                </button>
                <button
                  onClick={onVerify}
                  className="flex-1 py-3 bg-brand-cyan/20 hover:bg-brand-cyan/30 text-brand-cyan border border-brand-cyan/20 rounded-xl font-bold uppercase tracking-widest text-[10px] transition-colors"
                >
                  Verificar
                </button>
              </div>
            </div>
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  );
}

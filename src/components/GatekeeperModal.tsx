import { motion, AnimatePresence } from "framer-motion";
import { Lock, AlertTriangle } from "lucide-react";

interface GatekeeperModalProps {
  showInitialWarning: boolean;
  showGatekeeper: boolean;
  isAppUnlocked: boolean;
  contactsPassword: string;
  onContactsPasswordChange: (value: string) => void;
  onWarningAccepted: () => void;
  onUnlock: () => void;
}

export function GatekeeperModal({
  showInitialWarning,
  showGatekeeper,
  isAppUnlocked,
  contactsPassword,
  onContactsPasswordChange,
  onWarningAccepted,
  onUnlock,
}: GatekeeperModalProps) {
  return (
    <>
      {/* Aviso de Seguridad Inicial (Zero-Knowledge) */}
      <AnimatePresence>
        {showInitialWarning && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="absolute inset-0 bg-black/80 backdrop-blur-md"
            />
            <motion.div
              initial={{ opacity: 0, scale: 0.95, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: -20 }}
              className="relative w-full max-w-md bg-black border border-brand-amber-400/30 rounded-[32px] p-8 shadow-2xl overflow-hidden"
            >
              <div className="absolute top-0 left-1/2 -translate-x-1/2 w-32 h-32 bg-brand-amber-400/20 rounded-full blur-[50px] pointer-events-none" />

              <div className="relative flex flex-col items-center text-center">
                <div className="w-16 h-16 rounded-2xl bg-brand-amber-400/10 flex items-center justify-center border border-brand-amber-400/20 mb-6 text-brand-amber-400 shadow-inner">
                  <AlertTriangle className="w-8 h-8" />
                </div>

                <h2 className="text-xl font-bold mb-2">Aviso de Seguridad Crítico</h2>
                <p className="text-[10px] text-brand-amber-400 font-bold uppercase tracking-widest mb-6">Zero-Knowledge Architecture</p>

                <div className="bg-white/[0.02] border border-white/5 p-5 rounded-2xl mb-8 space-y-4 text-left">
                  <p className="text-sm text-white/80 leading-relaxed">
                    CryptoBro opera en un entorno de <strong className="text-white">memoria volátil</strong> para garantizar máxima seguridad.
                  </p>
                  <div className="flex gap-3 items-start">
                    <div className="w-1.5 h-1.5 rounded-full bg-red-400 mt-1.5 shrink-0" />
                    <p className="text-xs text-white/60 leading-relaxed">
                      <strong className="text-red-400">Si cierras la aplicación o regeneras la identidad</strong>, TODAS las claves activas (incluyendo contraseñas maestras y llaves cuánticas en uso) se destruirán irremediablemente.
                    </p>
                  </div>
                  <div className="flex gap-3 items-start">
                    <div className="w-1.5 h-1.5 rounded-full bg-brand-emerald mt-1.5 shrink-0" />
                    <p className="text-xs text-white/60 leading-relaxed">
                      Asegúrate de copiar y guardar tus llaves cuánticas generadas antes de salir. No hay forma de recuperarlas una vez cerrada la sesión y, sin ellas, te será imposible descifrar los archivos cifrados en la sesión en el futuro.
                    </p>
                  </div>
                </div>

                <button
                  onClick={onWarningAccepted}
                  className="w-full py-4 bg-brand-amber-400/10 hover:bg-brand-amber-400 text-brand-amber-400 hover:text-black font-bold uppercase tracking-widest text-xs rounded-xl transition-all duration-300 border border-brand-amber-400/30 hover:border-transparent"
                >
                  Entendido, asumo el riesgo
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* Gatekeeper / Pantalla de Desbloqueo Maestra */}
      <AnimatePresence>
        {showGatekeeper && !isAppUnlocked && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="absolute inset-0 bg-black/90 backdrop-blur-xl"
            />
            <motion.div
              initial={{ opacity: 0, scale: 0.95, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: -20 }}
              className="relative w-full max-w-md bg-black border border-brand-cyan/30 rounded-[32px] p-8 shadow-2xl overflow-hidden"
            >
              <div className="absolute top-0 left-1/2 -translate-x-1/2 w-32 h-32 bg-brand-cyan/20 rounded-full blur-[50px] pointer-events-none" />

              <div className="relative flex flex-col items-center text-center">
                <div className="w-16 h-16 rounded-2xl bg-brand-cyan/10 flex items-center justify-center border border-brand-cyan/20 mb-6 text-brand-cyan shadow-inner">
                  <Lock className="w-8 h-8" />
                </div>

                <h2 className="text-xl font-bold mb-2">Bóveda de Seguridad</h2>
                <p className="text-[10px] text-brand-cyan font-bold uppercase tracking-widest mb-6">Autenticación Requerida</p>

                <div className="bg-white/[0.02] border border-white/5 p-5 rounded-2xl mb-8 space-y-4 text-left w-full">
                  <p className="text-sm text-white/80 leading-relaxed">
                    Introduce tu <strong>Contraseña Maestra</strong>. Si es tu primera vez, la contraseña que introduzcas se convertirá en tu llave permanente.
                  </p>
                </div>

                <div className="w-full space-y-4">
                  <input
                    type="password"
                    value={contactsPassword}
                    onChange={(e) => onContactsPasswordChange(e.target.value)}
                    placeholder="Contraseña Maestra..."
                    className="w-full bg-[#111] border border-white/10 rounded-xl px-4 py-4 text-white placeholder-white/30 focus:outline-none focus:border-brand-cyan/50 focus:ring-1 focus:ring-brand-cyan/50 transition-all text-center"
                    autoFocus
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') onUnlock();
                    }}
                  />
                  <button
                    onClick={onUnlock}
                    className="w-full py-4 bg-brand-cyan/10 hover:bg-brand-cyan text-brand-cyan hover:text-black font-bold uppercase tracking-widest text-xs rounded-xl transition-all duration-300 border border-brand-cyan/30 hover:border-transparent"
                  >
                    Desbloquear CryptoBro
                  </button>
                </div>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </>
  );
}

import { motion, AnimatePresence } from "framer-motion";
import { HelpCircle, XCircle, Layers, Cpu, FileCode2, Globe, Trash2 } from "lucide-react";

interface SecurityGuideModalProps {
  show: boolean;
  onClose: () => void;
}

export function SecurityGuideModal({ show, onClose }: SecurityGuideModalProps) {
  return (
    <AnimatePresence>
      {show && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-6 bg-black/80 backdrop-blur-xl">
          <motion.div
            initial={{ opacity: 0, scale: 0.9, y: 20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.9, y: 20 }}
            className="w-full max-w-2xl bg-zinc-900 border border-white/10 rounded-[40px] overflow-hidden shadow-2xl"
          >
            <div className="p-10 space-y-8 max-h-[85vh] overflow-y-auto custom-scrollbar">
              <div className="flex justify-between items-start">
                <div className="flex items-center gap-4">
                  <div className="w-12 h-12 bg-brand-cyan/20 rounded-2xl flex items-center justify-center">
                    <HelpCircle className="text-brand-cyan w-6 h-6" />
                  </div>
                  <div>
                    <h2 className="text-2xl font-bold text-white">Guía de Seguridad</h2>
                    <p className="text-xs text-white/40 uppercase tracking-widest mt-1">Cómo funciona CryptoBro</p>
                  </div>
                </div>
                <button onClick={onClose} className="text-white/20 hover:text-white/60 transition-colors">
                  <XCircle className="w-8 h-8" />
                </button>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="bg-white/[0.02] border border-white/5 p-6 rounded-[24px] space-y-3">
                  <div className="flex items-center gap-2 text-brand-cyan">
                    <Layers className="w-4 h-4" />
                    <h3 className="text-xs font-bold uppercase tracking-widest">Cifrado Simétrico</h3>
                  </div>
                  <p className="text-[11px] text-white/60 leading-relaxed">
                    Usamos un sistema de <strong>doble capa</strong>: AES-256-GCM y ChaCha20-Poly1305. Cada bloque se cifra dos veces con diferentes algoritmos para garantizar que, si uno falla, el otro proteja tus datos.
                  </p>
                </div>

                <div className="bg-white/[0.02] border border-white/5 p-6 rounded-[24px] space-y-3">
                  <div className="flex items-center gap-2 text-brand-violet">
                    <Cpu className="w-4 h-4" />
                    <h3 className="text-xs font-bold uppercase tracking-widest">Post-Quantum</h3>
                  </div>
                  <p className="text-[11px] text-white/60 leading-relaxed">
                    Implementamos <strong>ML-KEM-1024</strong> (Kyber), el estándar de NIST contra ataques de ordenadores cuánticos. Las llaves tradicionales (RSA/ECC) serán vulnerables pronto; CryptoBro ya está protegido.
                  </p>
                </div>

                <div className="bg-white/[0.02] border border-white/5 p-6 rounded-[24px] space-y-3">
                  <div className="flex items-center gap-2 text-brand-emerald">
                    <FileCode2 className="w-4 h-4" />
                    <h3 className="text-xs font-bold uppercase tracking-widest">Firmas ML-DSA</h3>
                  </div>
                  <p className="text-[11px] text-white/60 leading-relaxed">
                    Cada archivo puede ser firmado con <strong>ML-DSA-65</strong> (Dilithium). Esto permite al receptor verificar que el archivo es auténtico y no ha sido modificado por terceros (Anti-Tampering).
                  </p>
                </div>

                <div className="bg-white/[0.02] border border-white/5 p-6 rounded-[24px] space-y-3">
                  <div className="flex items-center gap-2 text-brand-amber-400">
                    <Globe className="w-4 h-4" />
                    <h3 className="text-xs font-bold uppercase tracking-widest">Camuflaje</h3>
                  </div>
                  <p className="text-[11px] text-white/60 leading-relaxed">
                    El modo "Ocultar" permite inyectar tus contenedores <code>.vault</code> dentro de imágenes JPG o PNG. La imagen seguirá pareciendo normal, pero contendrá tus secretos ocultos al final del archivo.
                  </p>
                </div>
              </div>

              <div className="bg-red-500/5 border border-red-500/10 p-6 rounded-[24px] flex gap-4 items-center">
                <Trash2 className="w-10 h-10 text-red-500/40" />
                <div>
                  <h3 className="text-[10px] font-bold text-red-400 uppercase tracking-widest mb-1">Borrado Seguro (Shredding)</h3>
                  <p className="text-[11px] text-white/50 leading-snug">
                    Al habilitar esta opción, el archivo original se sobrescribe con <strong>3 pasadas</strong> (basado en el estándar <strong>DoD 5220.22-M</strong>: Ceros, Unos y Ruido aleatorio criptográfico) antes de ser eliminado, haciendo imposible su recuperación forense.
                  </p>
                </div>
              </div>

              <div className="text-center pt-4">
                <p className="text-[9px] text-white/20 uppercase tracking-[0.3em]">CryptoBro Security Framework v2.1 • 2026</p>
              </div>
            </div>
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  );
}

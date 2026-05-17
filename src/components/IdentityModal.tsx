import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { ask, save } from "@tauri-apps/plugin-dialog";
import { writeFile } from "@tauri-apps/plugin-fs";
import {
  XCircle,
  Fingerprint,
  Info,
  ShieldAlert,
  CheckCircle2,
  QrCode,
  Download,
} from "lucide-react";
import { cn } from "../utils";
import { toast } from "../toast";
import { Identity, ContactExportFile } from "../types";
import { QRCodeDisplay } from "./QRCodeDisplay";

interface IdentityModalProps {
  show: boolean;
  identity: Identity | null;
  showKeyGuide: boolean;
  onClose: () => void;
  onToggleGuide: () => void;
  onCopyKey: (text: string) => void | Promise<void>;
  onRegenerate: () => void;
  onDelete: () => void;
}

export function IdentityModal({
  show,
  identity,
  showKeyGuide,
  onClose,
  onToggleGuide,
  onCopyKey,
  onRegenerate,
  onDelete,
}: IdentityModalProps) {
  const [showShareQR, setShowShareQR] = useState(false);

  if (!identity) return null;

  const handleCopyAll = () => {
    const formattedKeys = `=== IDENTIDAD CUÁNTICA CRYPTOBRO ===
Protocolo: ML-KEM-1024 + ML-DSA-65

[ LLAVES DE CIFRADO (KEM) ]
Pública (Para recibir archivos - Compartible):
${identity.kem_pub}

Privada (Para abrir archivos - NO COMPARTIR):
${identity.kem_priv}

[ LLAVES DE FIRMA (DSA) ]
Pública (Para verificar tus archivos - Compartible):
${identity.dsa_pub}

Privada (Para firmar archivos - NO COMPARTIR):
${identity.dsa_priv}
====================================`;
    onCopyKey(formattedKeys);
  };

  const handleRegenerate = async () => {
    const ok = await ask("¿Estás seguro? Esto reemplazará tu identidad cuántica actual con una nueva.", {
      title: "Regenerar Identidad",
      kind: "warning",
    });
    if (ok) onRegenerate();
  };

  const handleDelete = async () => {
    const ok = await ask(
      "¿Eliminar la identidad cuántica de la memoria? Esta acción no se puede deshacer y no puedes recuperar las llaves si no las has guardado.",
      { title: "Eliminar Identidad", kind: "warning" }
    );
    if (ok) onDelete();
  };

  // Exportar tus llaves PÚBLICAS como archivo .cbrokey para compartir
  const handleExportPublicKeys = async () => {
    const outputPath = await save({
      title: "Exportar tu identidad pública",
      defaultPath: "Mi_Identidad_CryptoBro.cbrokey",
      filters: [{ name: "Identidad CryptoBro", extensions: ["cbrokey"] }],
    });
    if (!outputPath) return;

    const exportData: ContactExportFile = {
      app: "CryptoBro",
      v: 1,
      name: "Mi Identidad",
      kem_pub: identity.kem_pub,
      dsa_pub: identity.dsa_pub,
    };

    try {
      const json = JSON.stringify(exportData, null, 2);
      await writeFile(outputPath, new TextEncoder().encode(json));
      toast.success("Identidad pública exportada como .cbrokey");
    } catch (err) {
      toast.error("Error al exportar: " + String(err));
    }
  };

  return (
    <AnimatePresence>
      {show && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-6 bg-black/60 backdrop-blur-md">
          <motion.div
            initial={{ opacity: 0, scale: 0.9, y: 20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.9, y: 20 }}
            className="w-full max-w-xl bg-zinc-900 border border-white/10 rounded-[32px] overflow-hidden shadow-2xl"
          >
            <div className="p-8 space-y-6 max-h-[90vh] overflow-y-auto custom-scrollbar">
              {/* Cabecera del Modal */}
              <div className="flex justify-between items-start">
                <div>
                  <h2 className="text-xl font-bold text-white flex items-center gap-2">
                    <Fingerprint className="text-brand-cyan w-5 h-5" /> Tu Identidad Cuántica
                  </h2>
                  <p className="text-xs text-white/40 mt-1">Híbrida: ML-KEM-1024 + ML-DSA-65</p>
                </div>
                <div className="flex gap-2">
                  <button
                    onClick={onToggleGuide}
                    className={cn(
                      "w-8 h-8 rounded-full flex items-center justify-center transition-all",
                      showKeyGuide ? "bg-brand-cyan text-black" : "bg-white/5 text-white/40 hover:bg-white/10"
                    )}
                    title="¿Cómo usar estas llaves?"
                  >
                    <Info className="w-4 h-4" />
                  </button>
                  <button onClick={onClose} className="text-white/20 hover:text-white/60 transition-colors">
                    <XCircle className="w-6 h-6" />
                  </button>
                </div>
              </div>

              {/* Acordeón de Guía de Uso */}
              {showKeyGuide && (
                  <motion.div
                    initial={{ opacity: 0, y: -10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.2 }}
                  >
                    <div className="bg-brand-cyan/5 border border-brand-cyan/20 rounded-2xl p-5 space-y-4 text-[10px] leading-relaxed text-white/70">
                      <p className="font-bold text-brand-cyan uppercase tracking-widest text-[9px]">Protocolo de Uso de Llaves:</p>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div className="space-y-1">
                          <p className="text-white font-bold">1. Pública (Cifrado):</p>
                          <p>Dásela a tus contactos. Ellos la usarán para enviarte archivos que solo TÚ podrás abrir.</p>
                        </div>
                        <div className="space-y-1">
                          <p className="text-white font-bold">2. Privada (Cifrado):</p>
                          <p><strong>NUNCA LA COMPARTAS.</strong> Es la única llave capaz de abrir los archivos cifrados con tu llave pública.</p>
                        </div>
                        <div className="space-y-1">
                          <p className="text-white font-bold">3. Pública (Verificación):</p>
                          <p>Dásela a tus contactos. Ellos la usarán para confirmar que un archivo fue realmente firmado por ti.</p>
                        </div>
                        <div className="space-y-1">
                          <p className="text-white font-bold">4. Privada (Firma):</p>
                          <p><strong>SOLO TUYA.</strong> Se usa para poner un "sello digital" infalsificable en tus archivos antes de enviarlos.</p>
                        </div>
                      </div>
                    </div>
                  </motion.div>
              )}

              {/* ============================================ */}
              {/* SECCIÓN: COMPARTIR TU IDENTIDAD (QR Codes) */}
              {/* ============================================ */}
              <div className="space-y-3">
                <button
                  onClick={() => setShowShareQR(!showShareQR)}
                  className={cn(
                    "w-full flex items-center gap-3 p-4 rounded-2xl border transition-all",
                    showShareQR
                      ? "bg-brand-violet/10 border-brand-violet/30"
                      : "bg-white/[0.02] border-white/10 hover:border-brand-violet/20"
                  )}
                >
                  <div className={cn(
                    "p-2 rounded-xl transition-colors",
                    showShareQR ? "bg-brand-violet/20 text-brand-violet" : "bg-white/5 text-white/30"
                  )}>
                    <QrCode className="w-5 h-5" />
                  </div>
                  <div className="text-left flex-1">
                    <p className="text-xs font-bold text-white/80">Compartir tu Identidad Pública</p>
                    <p className="text-[9px] text-white/30">Muestra QR codes para que otros te añadan como contacto</p>
                  </div>
                </button>

                {showShareQR && (
                    <motion.div
                      initial={{ opacity: 0, y: -10 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ duration: 0.2 }}
                    >
                      <div className="space-y-4 pt-2">
                        {/* QR Codes de tus llaves públicas */}
                        <div className="grid grid-cols-2 gap-4">
                          <QRCodeDisplay
                            name="Mi Identidad"
                            keyHex={identity.kem_pub}
                            type="kem"
                            size={140}
                          />
                          <QRCodeDisplay
                            name="Mi Identidad"
                            keyHex={identity.dsa_pub}
                            type="dsa"
                            size={140}
                          />
                        </div>

                        {/* Botón exportar .cbrokey */}
                        <button
                          onClick={handleExportPublicKeys}
                          className="w-full py-2.5 bg-brand-violet/10 border border-brand-violet/20 rounded-xl text-[10px] font-bold uppercase tracking-widest text-brand-violet hover:bg-brand-violet/20 transition-all flex items-center justify-center gap-2"
                        >
                          <Download className="w-3.5 h-3.5" /> Exportar como .cbrokey
                        </button>

                        <p className="text-[9px] text-white/20 text-center italic">
                          Solo se exportan las llaves públicas. Tus llaves privadas nunca salen de tu dispositivo.
                        </p>
                      </div>
                    </motion.div>
                )}
              </div>

              {/* Rejilla de Llaves (KEM y DSA) */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* KEM Keys */}
                <div className="space-y-4">
                  <div className="space-y-2">
                    <div className="flex justify-between items-center text-[10px] font-bold text-brand-cyan uppercase tracking-widest px-1">
                      <span>Pública (Cifrado)</span>
                      <button onClick={() => onCopyKey(identity.kem_pub)} className="hover:text-white transition-colors">Copiar</button>
                    </div>
                    <div className="bg-black/40 border border-white/5 rounded-xl p-3 font-mono text-[8px] break-all leading-tight text-white/60 h-20 overflow-y-auto custom-scrollbar">
                      {identity.kem_pub}
                    </div>
                  </div>
                  <div className="space-y-2">
                    <div className="flex justify-between items-center text-[10px] font-bold text-brand-violet uppercase tracking-widest px-1">
                      <span>Privada (Cifrado)</span>
                      <button onClick={() => onCopyKey(identity.kem_priv)} className="hover:text-white transition-colors">Copiar</button>
                    </div>
                    <div className="bg-black/40 border border-white/5 rounded-xl p-3 font-mono text-[8px] break-all leading-tight text-white/40 h-20 overflow-y-auto custom-scrollbar">
                      {identity.kem_priv}
                    </div>
                  </div>
                </div>

                {/* DSA Keys */}
                <div className="space-y-4">
                  <div className="space-y-2">
                    <div className="flex justify-between items-center text-[10px] font-bold text-brand-emerald uppercase tracking-widest px-1">
                      <span>Pública (Verificación)</span>
                      <button onClick={() => onCopyKey(identity.dsa_pub)} className="hover:text-white transition-colors">Copiar</button>
                    </div>
                    <div className="bg-black/40 border border-white/5 rounded-xl p-3 font-mono text-[8px] break-all leading-tight text-white/60 h-20 overflow-y-auto custom-scrollbar">
                      {identity.dsa_pub}
                    </div>
                  </div>
                  <div className="space-y-2">
                    <div className="flex justify-between items-center text-[10px] font-bold text-brand-amber-400 uppercase tracking-widest px-1">
                      <span>Privada (Firma)</span>
                      <button onClick={() => onCopyKey(identity.dsa_priv)} className="hover:text-white transition-colors">Copiar</button>
                    </div>
                    <div className="bg-black/40 border border-white/5 rounded-xl p-3 font-mono text-[8px] break-all leading-tight text-white/40 h-20 overflow-y-auto custom-scrollbar">
                      {identity.dsa_priv}
                    </div>
                  </div>
                </div>
              </div>

              {/* Aviso de Estándar FIPS */}
              <div className="bg-white/5 border border-white/10 p-4 rounded-2xl flex gap-3">
                <ShieldAlert className="w-5 h-5 text-brand-cyan flex-shrink-0" />
                <p className="text-[10px] text-white/60 leading-snug">
                  <strong>FIPS-204 Standard:</strong> Esta identidad permite cifrado resistente a ordenadores cuánticos y firmas digitales infalsificables. Asegúrate de guardar las 4 llaves en un lugar seguro.
                </p>
              </div>

              {/* Acciones del Modal (Backup, Regenerar, Eliminar) */}
              <div className="pt-2 flex flex-col sm:flex-row gap-3">
                <button
                  onClick={handleCopyAll}
                  className="flex-[2] py-3 bg-brand-cyan text-black rounded-2xl text-[10px] font-bold uppercase tracking-widest hover:bg-brand-cyan/80 transition-all shadow-lg shadow-brand-cyan/20 flex items-center justify-center gap-2"
                >
                  <CheckCircle2 className="w-4 h-4" />
                  Copiar Todas las Llaves (Backup)
                </button>
                <button
                  onClick={handleRegenerate}
                  className="flex-1 py-3 bg-white/5 border border-white/10 rounded-2xl text-[10px] font-bold uppercase tracking-widest hover:bg-white/10 transition-all text-white/60"
                >
                  Regenerar
                </button>
                <button
                  onClick={handleDelete}
                  className="px-6 py-3 bg-red-500/10 border border-red-500/20 rounded-2xl text-[10px] font-bold uppercase tracking-widest hover:bg-red-500/20 transition-all text-red-400"
                >
                  Eliminar
                </button>
              </div>
            </div>
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  );
}

import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open, save } from "@tauri-apps/plugin-dialog";
import {
  Shield,
  Lock,
  Unlock,
  FileText,
  ChevronRight,
  Cpu,
  Activity,
  CheckCircle2,
  XCircle,
  FileCheck,
  ShieldAlert,
  Fingerprint,
  Zap,
  Key
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

interface ProcessState {
  status: 'idle' | 'processing' | 'success' | 'error';
  message: string;
}

export default function App() {
  const [password, setPassword] = useState("");
  const [quantumKey, setQuantumKey] = useState("");
  const [inputPath, setInputPath] = useState("");
  const [processState, setProcessState] = useState<ProcessState>({ status: 'idle', message: "" });
  const [mode, setMode] = useState<'encrypt' | 'decrypt'>('encrypt');
  const [itemType, setItemType] = useState<'file' | 'folder'>('file');
  const [cryptoMethod, setCryptoMethod] = useState<'password' | 'quantum'>('password');
  const [identity, setIdentity] = useState<{ pub: string, priv: string } | null>(null);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    alert("Copiado al portapapeles");
  };

  const handleGenerateIdentity = async () => {
    const res: any = await invoke("generate_quantum_keys");
    const [pub, priv] = res.data.split(':');
    setIdentity({ pub, priv });
  };

  const handleSelectFile = async () => {
    const selected = await open({
      multiple: false,
      directory: itemType === 'folder',
      filters: mode === 'decrypt' ? [{ name: 'Cifrado', extensions: ['vault'] }] : []
    });
    if (selected) {
      setInputPath(selected as string);
      setProcessState({ status: 'idle', message: "" });
    }
  };

  const runOperation = async () => {
    const secret = cryptoMethod === 'password' ? password : quantumKey;
    if (!inputPath || !secret) {
      setProcessState({ status: 'error', message: "Se requiere archivo/carpeta y llave/contraseña" });
      return;
    }

    setProcessState({ status: 'processing', message: mode === 'encrypt' ? "Asegurando..." : "Descifrando..." });

    try {
      let outputPath: string | null = "";
      
      if (mode === 'encrypt') {
        outputPath = await save({
          title: "Guardar contenedor seguro",
          defaultPath: inputPath + ".vault",
          filters: [{ name: 'Bóveda Cuántica', extensions: ['vault'] }]
        });
      } else {
        const defaultName = inputPath.replace(".vault", "");
        outputPath = await save({
          title: "Guardar archivo descifrado",
          defaultPath: defaultName,
        });
      }

      if (!outputPath) {
        setProcessState({ status: 'idle', message: "" });
        return;
      }

      // Elegir el comando basado en Método + Tipo + Modo
      let command = "";
      let args: any = { inputPath, outputPath };

      if (cryptoMethod === 'password') {
        command = itemType === 'file' 
          ? (mode === "encrypt" ? "encrypt_file" : "decrypt_file")
          : (mode === "encrypt" ? "encrypt_folder" : "decrypt_folder");
        args.password = password;
      } else {
        // En modo cuántico solo soportamos archivos por ahora para simplificar la lógica del contenedor
        command = mode === "encrypt" ? "encrypt_with_quantum" : "decrypt_with_quantum";
        if (mode === "encrypt") {
          args.publicKeyHex = quantumKey;
        } else {
          args.privateKeyHex = quantumKey;
        }
      }

      const result: any = await invoke(command, args);

      if (result.success) {
        setProcessState({ status: 'success', message: result.message });
        setInputPath("");
        setPassword("");
        setQuantumKey("");
      } else {
        setProcessState({ status: 'error', message: "Operación fallida" });
      }
    } catch (err: any) {
      setProcessState({ status: 'error', message: err.toString() });
    }
  };

  return (
    <div className="min-h-screen text-white flex flex-col items-center justify-center p-8 font-sans selection:bg-brand-cyan/30">

      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        className="w-full max-w-lg relative"
      >
        {/* Main Glass Card */}
        <div className="bg-black/40 backdrop-blur-3xl border border-white/10 rounded-[32px] shadow-2xl overflow-hidden">

          {/* Header Section */}
          <div className="p-8 pb-0 flex flex-col items-center text-center">
            <div className="w-20 h-20 rounded-3xl bg-gradient-to-br from-brand-cyan/20 to-brand-violet/20 flex items-center justify-center border border-white/10 mb-6 shadow-inner">
              <Shield className="w-10 h-10 text-brand-cyan" />
            </div>
            <h1 className="text-3xl font-bold tracking-tight mb-2">CryptoBro</h1>
            <div className="flex items-center gap-2 text-xs font-medium text-white/40 uppercase tracking-widest bg-white/5 px-3 py-1 rounded-full border border-white/5">
              <Fingerprint className="w-3 h-3" /> Seguridad Post-Cuántica
            </div>
          </div>

          {/* Mode & Method Selectors */}
          <div className="px-8 mt-10 space-y-4">
            <div className="bg-white/5 p-1 rounded-2xl flex border border-white/10">
              <button
                onClick={() => { setMode('encrypt'); setInputPath(""); }}
                className={cn(
                  "flex-1 py-3 rounded-xl text-sm font-semibold transition-all flex items-center justify-center gap-2",
                  mode === 'encrypt' ? "bg-white/10 text-brand-cyan shadow-lg border border-white/10" : "text-white/40 hover:text-white/60"
                )}
              >
                <Lock className="w-4 h-4" /> Cifrar
              </button>
              <button
                onClick={() => { setMode('decrypt'); setInputPath(""); }}
                className={cn(
                  "flex-1 py-3 rounded-xl text-sm font-semibold transition-all flex items-center justify-center gap-2",
                  mode === 'decrypt' ? "bg-white/10 text-brand-violet shadow-lg border border-white/10" : "text-white/40 hover:text-white/60"
                )}
              >
                <Unlock className="w-4 h-4" /> Descifrar
              </button>
            </div>

            <div className="flex items-center justify-between gap-4">
              <div className="flex gap-2">
                <button
                  onClick={() => { setItemType('file'); setInputPath(""); }}
                  className={cn(
                    "text-[10px] font-bold uppercase tracking-widest px-3 py-1.5 rounded-lg border transition-all flex items-center gap-2",
                    itemType === 'file' ? "border-brand-cyan/50 text-brand-cyan bg-brand-cyan/5" : "border-white/5 text-white/20 hover:text-white/40"
                  )}
                >
                  <FileText className="w-3 h-3" /> Archivo
                </button>
                <button
                  disabled={cryptoMethod === 'quantum'}
                  onClick={() => { setItemType('folder'); setInputPath(""); }}
                  className={cn(
                    "text-[10px] font-bold uppercase tracking-widest px-3 py-1.5 rounded-lg border transition-all flex items-center gap-2",
                    itemType === 'folder' ? "border-brand-cyan/50 text-brand-cyan bg-brand-cyan/5" : "border-white/5 text-white/20 hover:text-white/40",
                    cryptoMethod === 'quantum' && "opacity-20 cursor-not-allowed"
                  )}
                >
                  <Shield className="w-3 h-3" /> Carpeta
                </button>
              </div>

              <div className="flex gap-2">
                <button
                  onClick={() => { setCryptoMethod('password'); setInputPath(""); }}
                  className={cn(
                    "text-[10px] font-bold uppercase tracking-widest px-3 py-1.5 rounded-lg border transition-all flex items-center gap-2",
                    cryptoMethod === 'password' ? "border-brand-emerald/50 text-brand-emerald bg-brand-emerald/5" : "border-white/5 text-white/20 hover:text-white/40"
                  )}
                >
                  <Key className="w-3 h-3" /> Pass
                </button>
                <button
                  onClick={() => { setCryptoMethod('quantum'); setItemType('file'); setInputPath(""); }}
                  className={cn(
                    "text-[10px] font-bold uppercase tracking-widest px-3 py-1.5 rounded-lg border transition-all flex items-center gap-2",
                    cryptoMethod === 'quantum' ? "border-brand-cyan/50 text-brand-cyan bg-brand-cyan/5" : "border-white/5 text-white/20 hover:text-white/40"
                  )}
                >
                  <Zap className="w-3 h-3" /> PQC
                </button>
              </div>
            </div>
          </div>

          {/* Interaction Area */}
          <div className="p-8 space-y-6">

            {/* File Dropzone */}
            <motion.div
              whileHover={{ scale: 1.01 }}
              whileTap={{ scale: 0.99 }}
              onClick={handleSelectFile}
              className={cn(
                "relative group cursor-pointer h-40 rounded-[24px] border-2 border-dashed transition-all flex flex-col items-center justify-center p-6 text-center overflow-hidden",
                inputPath
                  ? "border-brand-cyan/40 bg-brand-cyan/5"
                  : "border-white/10 bg-white/[0.02] hover:bg-white/[0.04] hover:border-white/20"
              )}
            >
              <AnimatePresence mode="wait">
                {inputPath ? (
                  <motion.div
                    key="selected"
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="flex flex-col items-center gap-3"
                  >
                    <div className="p-3 bg-brand-cyan/20 rounded-2xl">
                      <FileCheck className="w-8 h-8 text-brand-cyan" />
                    </div>
                    <div>
                      <p className="text-sm font-medium text-brand-cyan truncate max-w-[280px]">
                        {inputPath.split('/').pop()}
                      </p>
                      <p className="text-[10px] text-white/40 uppercase mt-1">Listo para procesar</p>
                    </div>
                  </motion.div>
                ) : (
                  <motion.div
                    key="empty"
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    className="flex flex-col items-center gap-3"
                  >
                    <div className="p-3 bg-white/5 rounded-2xl group-hover:bg-white/10 transition-colors">
                      <FileText className="w-8 h-8 text-white/20" />
                    </div>
                    <div>
                      <p className="text-sm font-medium text-white/60">Selecciona el {itemType === 'file' ? 'archivo' : 'directorio'}</p>
                      <p className="text-xs text-white/30">O arrástralo directamente aquí</p>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </motion.div>

            {/* Secret Input */}
            <div className="space-y-3">
              <div className="flex items-center justify-between px-1">
                <label className="text-[11px] font-bold text-white/30 uppercase tracking-widest flex items-center gap-2">
                  <Cpu className="w-3 h-3" /> {cryptoMethod === 'password' ? 'Clave de Acceso' : (mode === 'encrypt' ? 'Llave Pública del Destinatario' : 'Tu Llave Privada')}
                </label>
                <ShieldAlert className="w-3 h-3 text-white/20" />
              </div>
              
              {cryptoMethod === 'password' ? (
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Mínimo 12 caracteres recomendados..."
                  className="w-full bg-white/5 border border-white/10 rounded-2xl px-6 py-4 focus:outline-none focus:ring-2 focus:ring-brand-cyan/20 transition-all placeholder:text-white/10 text-sm tracking-widest font-mono"
                />
              ) : (
                <textarea
                  value={quantumKey}
                  onChange={(e) => setQuantumKey(e.target.value)}
                  placeholder={mode === 'encrypt' ? "Pega aquí la llave pública hexadecimal..." : "Pega aquí tu llave privada hexadecimal..."}
                  className="w-full h-24 bg-white/5 border border-white/10 rounded-2xl px-6 py-4 focus:outline-none focus:ring-2 focus:ring-brand-cyan/20 transition-all placeholder:text-white/10 text-[10px] leading-tight font-mono resize-none"
                />
              )}
            </div>

            {/* Execute Button */}
            <div className="pt-2">
              <button
                disabled={processState.status === 'processing'}
                onClick={runOperation}
                className={cn(
                  "w-full h-16 rounded-2xl font-bold text-lg flex items-center justify-center gap-3 transition-all relative overflow-hidden group",
                  mode === 'encrypt'
                    ? "bg-brand-cyan text-black"
                    : "bg-brand-violet text-white",
                  processState.status === 'processing' && "opacity-50 cursor-wait"
                )}
              >
                {processState.status === 'processing' ? (
                  <div className="flex items-center gap-3">
                    <Activity className="w-5 h-5 animate-pulse" />
                    <span>PROCESANDO...</span>
                  </div>
                ) : (
                  <>
                    <span>{mode === 'encrypt' ? 'CIFRAR AHORA' : 'DESCIFRAR AHORA'}</span>
                    <ChevronRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
                  </>
                )}

                {/* Button Glow Effect */}
                <div className={cn(
                  "absolute inset-0 opacity-0 group-hover:opacity-20 transition-opacity",
                  mode === 'encrypt' ? "bg-white" : "bg-brand-cyan"
                )} />
              </button>
            </div>

            {/* Status Feedback */}
            <AnimatePresence>
              {processState.status !== 'idle' && processState.status !== 'processing' && (
                <motion.div
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: 10 }}
                  className={cn(
                    "p-5 rounded-2xl flex items-start gap-4 text-sm border",
                    processState.status === 'success' && "bg-brand-emerald/10 border-brand-emerald/20 text-brand-emerald",
                    processState.status === 'error' && "bg-red-500/10 border-red-500/20 text-red-400"
                  )}
                >
                  {processState.status === 'success' ? <CheckCircle2 className="w-5 h-5 mt-0.5" /> : <XCircle className="w-5 h-5 mt-0.5" />}
                  <div className="flex-1">
                    <p className="font-bold uppercase text-[10px] tracking-widest mb-1">
                      {processState.status === 'success' ? 'Resultado Exitoso' : 'Error del Sistema'}
                    </p>
                    <p className="opacity-80 leading-relaxed text-xs">{processState.message}</p>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          {/* Footer Info Bars */}
          <div className="flex border-t border-white/5 divide-x divide-white/5 bg-white/[0.02]">
            <div className="flex-1 p-4 flex flex-col items-center">
              <span className="text-[9px] text-white/30 uppercase font-bold tracking-tighter">Cifrado</span>
              <span className="text-[10px] font-medium text-white/60">AES+ChaCha20</span>
            </div>
            <div className="flex-1 p-4 flex flex-col items-center group cursor-pointer hover:bg-white/5 transition-colors"
              onClick={handleGenerateIdentity}>
              <span className="text-[9px] text-white/30 uppercase font-bold tracking-tighter">Identidad PQC</span>
              <span className="text-[10px] font-medium text-brand-cyan">Generar Par</span>
            </div>
          </div>
        </div>

        {/* Identity Modal */}
        <AnimatePresence>
          {identity && (
            <div className="fixed inset-0 z-50 flex items-center justify-center p-6 bg-black/60 backdrop-blur-md">
              <motion.div 
                initial={{ opacity: 0, scale: 0.9, y: 20 }}
                animate={{ opacity: 1, scale: 1, y: 0 }}
                exit={{ opacity: 0, scale: 0.9, y: 20 }}
                className="w-full max-w-lg bg-zinc-900 border border-white/10 rounded-[32px] overflow-hidden shadow-2xl"
              >
                <div className="p-8 space-y-6">
                  <div className="flex justify-between items-start">
                    <div>
                      <h2 className="text-xl font-bold text-white flex items-center gap-2">
                        <Fingerprint className="text-brand-cyan w-5 h-5" /> Tu Identidad Cuántica
                      </h2>
                      <p className="text-xs text-white/40 mt-1">Generada con ML-KEM-1024</p>
                    </div>
                    <button onClick={() => setIdentity(null)} className="text-white/20 hover:text-white/60 transition-colors">
                      <XCircle className="w-6 h-6" />
                    </button>
                  </div>

                  <div className="space-y-4">
                    <div className="space-y-2">
                      <div className="flex justify-between items-center text-[10px] font-bold text-brand-cyan uppercase tracking-widest px-1">
                        <span>Llave Pública (Compartir)</span>
                        <button onClick={() => copyToClipboard(identity.pub)} className="hover:text-white transition-colors">Copiar</button>
                      </div>
                      <div className="bg-black/40 border border-white/5 rounded-xl p-4 font-mono text-[9px] break-all leading-relaxed text-white/60 h-24 overflow-y-auto custom-scrollbar">
                        {identity.pub}
                      </div>
                    </div>

                    <div className="space-y-2">
                      <div className="flex justify-between items-center text-[10px] font-bold text-brand-violet uppercase tracking-widest px-1">
                        <span>Llave Privada (¡SECRETA!)</span>
                        <button onClick={() => copyToClipboard(identity.priv)} className="hover:text-white transition-colors">Copiar</button>
                      </div>
                      <div className="bg-black/40 border border-white/5 rounded-xl p-4 font-mono text-[9px] break-all leading-relaxed text-white/60 h-24 overflow-y-auto custom-scrollbar">
                        {identity.priv}
                      </div>
                    </div>
                  </div>

                  <div className="bg-brand-violet/10 border border-brand-violet/20 p-4 rounded-2xl flex gap-3">
                    <ShieldAlert className="w-5 h-5 text-brand-violet flex-shrink-0" />
                    <p className="text-[10px] text-brand-violet/80 leading-snug">
                      <strong>Importante:</strong> CryptoBro no guarda estas llaves. Si cierras esta ventana sin copiarlas, se perderán para siempre. La llave pública es la que entregas a otros; la privada es solo tuya.
                    </p>
                  </div>
                </div>
              </motion.div>
            </div>
          )}
        </AnimatePresence>

        {/* Subtle Bottom Credits */}
        <p className="text-center mt-6 text-[10px] text-white/20 uppercase tracking-[0.4em]">
          CryptoBro • Post-Quantum Secure Vault • Local-First
        </p>
      </motion.div>
    </div>
  );
}

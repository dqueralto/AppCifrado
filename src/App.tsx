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
  ShieldAlert,
  Fingerprint,
  Zap,
  Key,
  Users,
  Trash2,
  HelpCircle,
  Info,
  Layers,
  Globe,
  FileCode2,
  User
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

interface Identity {
  kem_pub: string;
  kem_priv: string;
  dsa_pub: string;
  dsa_priv: string;
}

export default function App() {
  /* 
   * ESTADOS DE LA APLICACIÓN:
   * La UI gestiona el flujo de trabajo de cifrado post-cuántico mediante estados atómicos.
   * - cryptoMethod: Permite elegir entre cifrado de contraseña tradicional o PQC.
   * - identity: Mantiene en memoria las llaves ML-KEM (encapsulación) y ML-DSA (firma).
   * - mode: Define si estamos procesando archivos o realizando esteganografía.
   */
  const [password, setPassword] = useState("");
  const [quantumKey, setQuantumKey] = useState("");
  const [verifierKey, setVerifierKey] = useState("");
  const [inputPath, setInputPath] = useState("");
  const [processState, setProcessState] = useState<ProcessState>({ status: 'idle', message: "" });
  const [mode, setMode] = useState<'encrypt' | 'decrypt' | 'stego'>('encrypt');
  const [itemType, setItemType] = useState<'file' | 'folder'>('file');
  const [cryptoMethod, setCryptoMethod] = useState<'password' | 'quantum'>('password');
  const [identity, setIdentity] = useState<Identity | null>(null);
  const [shredOriginal, setShredOriginal] = useState(false);
  const [contacts, setContacts] = useState<{ name: string, public_key: string }[]>([]);
  const [showContacts, setShowContacts] = useState(false);
  const [newContact, setNewContact] = useState({ name: "", key: "" });
  const [stegoAction, setStegoAction] = useState<'hide' | 'extract'>('hide');
  const [showGuide, setShowGuide] = useState(false);
  const [showKeyGuide, setShowKeyGuide] = useState(false);
  const [showIdentityModal, setShowIdentityModal] = useState(false);
  const [carrierPath, setCarrierPath] = useState("");
  const [contactsPassword, setContactsPassword] = useState(""); // Contraseña de la libreta
  const [isContactsUnlocked, setIsContactsUnlocked] = useState(false); // Estado de desbloqueo
  const [copiedContact, setCopiedContact] = useState<string | null>(null); // Para feedback de copia
  const [copiedToast, setCopiedToast] = useState(false); // Toast de copiado en portapapeles

  // Función segura para cerrar la libreta: borra SIEMPRE el estado de autenticación.
  // Esto garantiza que cada apertura del modal requiere contraseña, sin importar
  // si la app fue minimizada, el modal fue cerrado o se vuelve a abrir en la misma sesión.
  const closeContacts = () => {
    setShowContacts(false);
    setIsContactsUnlocked(false);
    setContactsPassword("");
    setContacts([]);
  };

  const loadContacts = async (pass?: string) => {
    const p = pass || contactsPassword;
    // Seguridad: nunca intentar cargar sin contraseña
    if (!p) {
      setProcessState({ status: 'error', message: "Introduce la contraseña de la libreta" });
      return;
    }
    try {
      const list: any = await invoke("get_contacts", { password: p });
      setContacts(list);
      setIsContactsUnlocked(true);
    } catch (err) {
      setProcessState({ status: 'error', message: "Contraseña de contactos incorrecta o error de acceso" });
      setIsContactsUnlocked(false);
      setContacts([]);
    }
  };

  const handleAddContact = async () => {
    if (!newContact.name || !newContact.key || !contactsPassword) return;
    try {
      await invoke("save_contact", { 
        password: contactsPassword, 
        name: newContact.name, 
        publicKey: newContact.key 
      });
      setNewContact({ name: "", key: "" });
      loadContacts();
    } catch (err) {
      setProcessState({ status: 'error', message: String(err) });
    }
  };

  const handleDeleteContact = async (name: string) => {
    try {
      await invoke("delete_contact", { password: contactsPassword, name });
      loadContacts();
    } catch (err) {
      setProcessState({ status: 'error', message: String(err) });
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedToast(true);
    setTimeout(() => setCopiedToast(false), 2000);
  };

  const handleGenerateIdentity = async () => {
    try {
      const result: any = await invoke("generate_quantum_keys");
      if (result.success && result.data) {
        const [kp, ks, dp, ds] = result.data.split(":");
        setIdentity({ kem_pub: kp, kem_priv: ks, dsa_pub: dp, dsa_priv: ds });
        setShowKeyGuide(false);
        setShowIdentityModal(true);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleSelectFile = async () => {
    const selected = await open({
      multiple: false,
      directory: itemType === 'folder',
      filters: mode === 'decrypt' ? [{ name: 'Cifrado', extensions: ['vault'] }] : (mode === 'stego' && stegoAction === 'hide' ? [{ name: 'Bóveda', extensions: ['vault'] }] : [])
    });
    if (selected) {
      setInputPath(selected as string);
      setProcessState({ status: 'idle', message: "" });
    }
  };

  const handleSelectCarrier = async () => {
    const selected = await open({
      multiple: false,
      title: "Selecciona Archivo de Camuflaje (Imagen, Audio, Video)",
      filters: [{ name: 'Multimedia', extensions: ['jpg', 'jpeg', 'png', 'mp3', 'mp4', 'mkv', 'pdf'] }]
    });
    if (selected) {
      setCarrierPath(selected as string);
    }
  };

  /**
   * LÓGICA DE OPERACIÓN:
   * La aplicación implementa cifrado híbrido post-cuántico.
   * 1. ML-KEM (FIPS 203): Utilizado para la encapsulación de llaves. Es resistente a ataques de computación cuántica (algoritmo Kyber).
   * 2. ML-DSA (FIPS 204): Utilizado para la firma digital de los archivos. Asegura la autenticidad del remitente (algoritmo Dilithium).
   * 3. Cascade Encryption: El secreto compartido derivado de ML-KEM se utiliza como semilla para algoritmos simétricos (AES-256-GCM y ChaCha20).
   */
  const runOperation = async () => {
    const secret = cryptoMethod === 'password' ? password : quantumKey;
    if (mode !== 'stego' && (!inputPath || !secret)) {
      setProcessState({ status: 'error', message: "Se requiere archivo/carpeta y llave/contraseña" });
      return;
    }
    
    if (mode === 'stego' && !inputPath) {
      setProcessState({ status: 'error', message: "Selecciona primero el archivo .vault o la imagen" });
      return;
    }

    setProcessState({ status: 'processing', message: mode === 'encrypt' ? "Asegurando..." : "Descifrando..." });

    try {
      let outputPath: string | null = "";

      if (mode === 'stego') {
        if (stegoAction === 'hide') {
          if (!carrierPath) {
            setProcessState({ status: 'error', message: "Se requiere un archivo de camuflaje" });
            return;
          }
          
          /* 
           * PQC IMPLEMENTATION - STEP 1 (ENCAPSULACIÓN):
           * Encapsular usando ML-KEM-1024 (FIPS 203).
           * Genera un secreto compartido y un texto cifrado que solo el dueño de la llave privada puede abrir.
           * let (ciphertext, shared_secret) = pk.encapsulate(&mut OsRng);
           *
           * PQC IMPLEMENTATION - STEP 2 (DERIVACIÓN):
           * El secreto compartido generado por ML-KEM es la semilla de entropía para derivar 
           * nuestras llaves simétricas (AES+ChaCha).
           */

          outputPath = await save({
            title: "Guardar archivo camuflado",
            defaultPath: "secreto_oculto",
            filters: [{ name: 'Todos los archivos', extensions: ['*'] }]
          });
          if (!outputPath) return;

          const result: any = await invoke("hide_in_image", {
            imagePath: carrierPath,
            vaultPath: inputPath,
            outputPath
          });

          if (result.success) setProcessState({ status: 'success', message: result.message });
          else setProcessState({ status: 'error', message: "Error al ocultar" });
        } else {
          // Extraer vault de imagen
          outputPath = await save({
            title: "Guardar contenedor extraído",
            defaultPath: "extraido.vault",
            filters: [{ name: 'Bóveda', extensions: ['vault'] }]
          });
          if (!outputPath) return;

          const result: any = await invoke("extract_from_image", {
            imagePath: inputPath,
            outputVaultPath: outputPath
          });

          if (result.success) setProcessState({ status: 'success', message: result.message });
          else setProcessState({ status: 'error', message: "Error al extraer: No se encontraron datos" });
        }
        return;
      }

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
        // Modo cuántico
        if (itemType === 'file') {
          command = mode === "encrypt" ? "encrypt_with_quantum" : "decrypt_with_quantum";
        } else {
          command = mode === "encrypt" ? "encrypt_folder_with_quantum" : "decrypt_folder_with_quantum";
        }

        if (mode === "encrypt") {
          args.publicKeyHex = quantumKey;
          // Si tenemos nuestra identidad cargada, firmamos automáticamente
          if (identity) {
            args.signingKeyHex = `${identity.dsa_pub}:${identity.dsa_priv}`;
          }
        } else {
          args.privateKeyHex = quantumKey;
          // El usuario puede pegar la llave de verificación en un campo opcional (o la usamos de contactos)
          // Por ahora, si tenemos una llave cargada en un estado nuevo 'verifierKey', la usamos.
          if (verifierKey) {
            args.verifierKeyHex = verifierKey;
          }
        }
      }

      if (mode === 'encrypt') {
        args.shredOriginal = shredOriginal;
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
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="w-full max-w-5xl relative"
      >
        {/* Main Glass Card */}
        <div className="bg-black/40 backdrop-blur-3xl border border-white/10 rounded-[40px] shadow-2xl overflow-hidden flex flex-col md:flex-row min-h-[650px]">
          
          {/* Sidebar / Left Column: Controls & File Selection */}
          <div className="w-full md:w-5/12 border-r border-white/5 bg-white/[0.02] flex flex-col p-8">
            {/* Header Mini */}
            <div className="flex items-center gap-4 mb-8">
              <div className="w-12 h-12 rounded-2xl bg-brand-cyan/20 flex items-center justify-center border border-white/10 shadow-inner">
                <Shield className="w-6 h-6 text-brand-cyan" />
              </div>
              <div>
                <h1 className="text-2xl font-bold tracking-tight">CryptoBro</h1>
                <p className="text-[10px] text-white/40 font-bold uppercase tracking-widest">Suite de Seguridad</p>
              </div>
            </div>

            {/* Mode Selector */}
            <div className="space-y-6 flex-1">
              <div className="space-y-2">
                <p className="text-[10px] font-bold text-white/20 uppercase tracking-widest px-1">Operación Principal</p>
                <div className="bg-white/5 p-1 rounded-2xl flex border border-white/10">
                  <button
                    onClick={() => { setMode('encrypt'); setInputPath(""); }}
                    className={cn(
                      "flex-1 py-2 rounded-xl text-xs font-semibold transition-all flex items-center justify-center gap-2",
                      mode === 'encrypt' ? "bg-white/10 text-brand-cyan shadow-lg border border-white/10" : "text-white/40 hover:text-white/60"
                    )}
                  >
                    <Lock className="w-3.5 h-3.5" /> Cifrar
                  </button>
                  <button
                    onClick={() => { setMode('decrypt'); setInputPath(""); }}
                    className={cn(
                      "flex-1 py-2 rounded-xl text-xs font-semibold transition-all flex items-center justify-center gap-2",
                      mode === 'decrypt' ? "bg-white/10 text-brand-violet shadow-lg border border-white/10" : "text-white/40 hover:text-white/60"
                    )}
                  >
                    <Unlock className="w-3.5 h-3.5" /> Descifrar
                  </button>
                  <button
                    onClick={() => { setMode('stego'); setInputPath(""); }}
                    className={cn(
                      "flex-1 py-2 rounded-xl text-xs font-semibold transition-all flex items-center justify-center gap-2",
                      mode === 'stego' ? "bg-white/10 text-brand-emerald shadow-lg border border-white/10" : "text-white/40 hover:text-white/60"
                    )}
                  >
                    <Zap className="w-3.5 h-3.5" /> Ocultar
                  </button>
                </div>
              </div>

              {/* File Dropzone - Integrated in Sidebar */}
              <div className="space-y-3">
                <p className="text-[10px] font-bold text-white/20 uppercase tracking-widest px-1">Entrada de Datos</p>
                
                {mode !== 'stego' && (
                  <div className="flex gap-2 mb-2">
                    <button
                      onClick={() => { setItemType('file'); setInputPath(""); }}
                      className={cn(
                        "flex-1 text-[9px] font-bold uppercase tracking-widest py-2 rounded-lg border transition-all flex items-center justify-center gap-2",
                        itemType === 'file' ? "border-brand-cyan/50 text-brand-cyan bg-brand-cyan/5" : "border-white/5 text-white/20 hover:text-white/40"
                      )}
                    >
                      <FileText className="w-3 h-3" /> Archivo
                    </button>
                    <button
                      onClick={() => { setItemType('folder'); setInputPath(""); }}
                      className={cn(
                        "flex-1 text-[9px] font-bold uppercase tracking-widest py-2 rounded-lg border transition-all flex items-center justify-center gap-2",
                        itemType === 'folder' ? "border-brand-cyan/50 text-brand-cyan bg-brand-cyan/5" : "border-white/5 text-white/20 hover:text-white/40"
                      )}
                    >
                      <Shield className="w-3 h-3" /> Carpeta
                    </button>
                  </div>
                )}

                <div className={cn(
                  "group relative overflow-hidden rounded-[24px] border border-dashed transition-all duration-500",
                  inputPath ? "bg-white/5 border-brand-cyan/30" : "bg-white/[0.02] border-white/10 hover:border-white/20"
                )}>
                  <button onClick={handleSelectFile} className="w-full p-6 flex flex-col items-center justify-center gap-3">
                    <div className={cn(
                      "w-10 h-10 rounded-xl flex items-center justify-center transition-all",
                      inputPath ? "bg-brand-cyan text-black" : "bg-white/5 text-white/20"
                    )}>
                      {itemType === 'file' ? <FileText className="w-5 h-5" /> : <Shield className="w-5 h-5" />}
                    </div>
                    <p className="text-[10px] font-bold text-white/60 tracking-wide uppercase text-center px-2">
                      {inputPath ? inputPath.split('/').pop() : `Seleccionar ${itemType === 'file' ? 'Archivo' : 'Carpeta'}`}
                    </p>
                  </button>
                </div>

                {mode === 'stego' && stegoAction === 'hide' && (
                  <div className={cn(
                    "group relative overflow-hidden rounded-[24px] border border-dashed transition-all duration-500 mt-2",
                    carrierPath ? "bg-white/5 border-brand-emerald/30" : "bg-white/[0.02] border-white/10 hover:border-white/20"
                  )}>
                    <button onClick={handleSelectCarrier} className="w-full p-6 flex flex-col items-center justify-center gap-3">
                      <div className={cn(
                        "w-10 h-10 rounded-xl flex items-center justify-center transition-all",
                        carrierPath ? "bg-brand-emerald text-black" : "bg-white/5 text-white/20"
                      )}>
                        <Globe className="w-5 h-5" />
                      </div>
                      <p className="text-[10px] font-bold text-white/60 tracking-wide uppercase text-center">
                        {carrierPath ? carrierPath.split('/').pop() : 'Archivo de Camuflaje'}
                      </p>
                    </button>
                  </div>
                )}
              </div>
            </div>

            {/* Bottom Actions */}
            <div className="mt-8 pt-6 border-t border-white/5 flex justify-between items-center">
              <div className="flex gap-4">
                <button onClick={() => setShowGuide(true)} className="text-[9px] font-bold text-white/20 hover:text-brand-cyan uppercase flex items-center gap-1.5 transition-colors">
                  <HelpCircle className="w-3 h-3" /> Guía
                </button>
                <button onClick={() => setShowContacts(true)} className="text-[9px] font-bold text-white/20 hover:text-brand-cyan uppercase flex items-center gap-1.5 transition-colors">
                  <Users className="w-3 h-3" /> Contactos
                </button>
              </div>
              <div className="text-[9px] text-white/10 font-bold uppercase tracking-tighter">V0.1.0-STABLE</div>
            </div>
          </div>

          {/* Right Column: Key Configuration & Execution */}
          <div className="flex-1 p-8 flex flex-col">
            
            {/* Context Title */}
            <div className="mb-10 flex justify-between items-end">
              <div>
                <p className="text-[10px] font-bold text-brand-cyan uppercase tracking-[0.2em] mb-1">Configuración</p>
                <h2 className="text-xl font-bold text-white">Parámetros de Seguridad</h2>
              </div>
              {identity && (
                <div className="px-3 py-1 bg-brand-emerald/10 border border-brand-emerald/20 rounded-full flex items-center gap-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-brand-emerald animate-pulse" />
                  <span className="text-[9px] font-bold text-brand-emerald uppercase tracking-widest">Identidad PQC Activa</span>
                </div>
              )}
            </div>

            <div className="flex-1 space-y-8">
              {/* Method Switcher (inside right col) */}
              {mode !== 'stego' && (
                <div className="flex gap-2">
                  <button
                    onClick={() => { setCryptoMethod('password'); }}
                    className={cn(
                      "flex-1 py-3 rounded-2xl border transition-all flex flex-col items-center gap-2",
                      cryptoMethod === 'password' ? "bg-brand-emerald/5 border-brand-emerald/30 text-brand-emerald" : "bg-white/5 border-white/5 text-white/20"
                    )}
                  >
                    <Key className="w-5 h-5" />
                    <span className="text-[9px] font-bold uppercase tracking-widest">Contraseña</span>
                  </button>
                  <button
                    onClick={() => { setCryptoMethod('quantum'); setItemType('file'); }}
                    className={cn(
                      "flex-1 py-3 rounded-2xl border transition-all flex flex-col items-center gap-2",
                      cryptoMethod === 'quantum' ? "bg-brand-cyan/5 border-brand-cyan/30 text-brand-cyan" : "bg-white/5 border-white/5 text-white/20"
                    )}
                  >
                    <Zap className="w-5 h-5" />
                    <span className="text-[9px] font-bold uppercase tracking-widest">Post-Cuántico</span>
                  </button>
                </div>
              )}

              {/* Dynamic Inputs Based on Selection */}
              <div className="space-y-6">
                {mode === 'stego' ? (
                  <div className="space-y-4 py-10 text-center">
                    <div className="w-16 h-16 bg-brand-emerald/10 rounded-full flex items-center justify-center mx-auto mb-4">
                      <Zap className="text-brand-emerald w-8 h-8" />
                    </div>
                    <h3 className="text-lg font-bold">Esteganografía Activa</h3>
                    <p className="text-xs text-white/40 max-w-xs mx-auto">
                      {stegoAction === 'hide' 
                        ? 'Oculta tu bóveda cifrada concatenándola detrás del stream de datos de un archivo multimedia legítimo.' 
                        : 'Analiza un archivo multimedia en busca del marcador de inicio de CryptoBro para extraer la bóveda oculta.'}
                    </p>
                    <div className="flex justify-center gap-4 pt-4">
                      <button onClick={() => setStegoAction('hide')} className={cn("px-4 py-2 rounded-lg text-[9px] font-bold uppercase tracking-widest border transition-all", stegoAction === 'hide' ? "bg-brand-emerald/20 border-brand-emerald/40 text-brand-emerald" : "bg-white/5 border-white/5 text-white/20")}>Ocultar</button>
                      <button onClick={() => setStegoAction('extract')} className={cn("px-4 py-2 rounded-lg text-[9px] font-bold uppercase tracking-widest border transition-all", stegoAction === 'extract' ? "bg-brand-emerald/20 border-brand-emerald/40 text-brand-emerald" : "bg-white/5 border-white/5 text-white/20")}>Extraer</button>
                    </div>
                  </div>
                ) : (
                  <>
                    {cryptoMethod === 'password' ? (
                      <div className="space-y-3">
                        <div className="flex justify-between items-center px-1">
                          <p className="text-[10px] font-bold text-white/40 uppercase tracking-widest">Contraseña Maestra</p>
                          <span className="text-[9px] text-brand-emerald font-bold uppercase">Argon2id + AES-256</span>
                        </div>
                        <input
                          type="password"
                          value={password}
                          onChange={(e) => setPassword(e.target.value)}
                          placeholder="Mínimo 12 caracteres..."
                          className="w-full bg-white/5 border border-white/10 rounded-2xl px-6 py-4 focus:outline-none focus:ring-2 focus:ring-brand-emerald/20 text-sm font-mono tracking-widest"
                        />
                      </div>
                    ) : (
                      <div className="space-y-4">
                        <div className="space-y-1">
                          <p className="text-[9px] text-white/40 uppercase px-1">{mode === 'encrypt' ? 'Llave Pública del Recipiente (KEM)' : 'Tu Llave Privada (KEM)'}</p>
                          <textarea
                            value={quantumKey}
                            onChange={(e) => setQuantumKey(e.target.value)}
                            className="w-full h-32 bg-white/5 border border-white/10 rounded-2xl px-6 py-4 focus:outline-none focus:ring-2 focus:ring-brand-cyan/20 text-[10px] font-mono leading-tight resize-none"
                            placeholder="Pega la llave hexadecimal aquí..."
                          />
                        </div>
                        {mode === 'decrypt' && (
                          <div className="space-y-1">
                            <p className="text-[9px] text-white/40 uppercase px-1">Firma del Remitente (DSA) - Opcional</p>
                            <textarea
                              value={verifierKey}
                              onChange={(e) => setVerifierKey(e.target.value)}
                              className="w-full h-16 bg-white/5 border border-white/10 rounded-2xl px-6 py-4 focus:outline-none focus:ring-2 focus:ring-brand-emerald/20 text-[9px] font-mono leading-tight resize-none"
                              placeholder="Llave de verificación..."
                            />
                          </div>
                        )}
                        {mode === 'encrypt' && contacts.length > 0 && (
                          <div className="flex flex-wrap gap-2 pt-1">
                            {contacts.map(c => (
                              <button key={c.name} onClick={() => setQuantumKey(c.public_key)} className="text-[8px] px-2 py-1 rounded bg-white/5 border border-white/5 hover:border-brand-cyan/30 text-white/40 hover:text-brand-cyan transition-all uppercase font-bold tracking-widest">{c.name}</button>
                            ))}
                          </div>
                        )}
                      </div>
                    )}
                  </>
                )}
              </div>
            </div>

            {/* Final Action Area */}
            <div className="mt-8 pt-8 border-t border-white/5 space-y-4">
              <div className="flex items-center justify-between">
                {mode === 'encrypt' && (
                  <div 
                    onClick={() => setShredOriginal(!shredOriginal)}
                    className="flex items-center gap-3 cursor-pointer group"
                  >
                    <div className={cn("w-5 h-5 rounded-md flex items-center justify-center border transition-all", shredOriginal ? "bg-red-500/20 border-red-500 text-red-500" : "bg-white/5 border-white/10 text-transparent")}>
                      <Trash2 className="w-3 h-3" />
                    </div>
                    <span className={cn("text-[10px] font-bold uppercase tracking-widest transition-colors", shredOriginal ? "text-red-400" : "text-white/20 group-hover:text-white/40")}>Borrado Seguro DoD 5220.22-M</span>
                  </div>
                )}
                {identity && (
                  <button onClick={() => setShowIdentityModal(true)} className="text-[10px] font-bold text-brand-cyan/60 hover:text-brand-cyan uppercase tracking-widest flex items-center gap-2">
                    <User className="w-3.5 h-3.5" /> Ver Mi ID
                  </button>
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
                      <span>
                        {mode === 'stego'
                          ? (stegoAction === 'hide' ? 'CAMUFLAR AHORA' : 'EXTRAER AHORA')
                          : (mode === 'encrypt' ? 'CIFRAR AHORA' : 'DESCIFRAR AHORA')}
                      </span>
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
          </div>

          {/* Footer Info Bars */}
          <div className="flex border-t border-white/5 divide-x divide-white/5 bg-white/[0.02]">
            <div className="flex-1 p-4 flex flex-col items-center">
              <span className="text-[9px] text-white/30 uppercase font-bold tracking-tighter">Cifrado</span>
              <span className="text-[10px] font-medium text-white/60">AES+ChaCha20</span>
            </div>
            <div 
              className="flex-1 p-4 flex flex-col items-center group cursor-pointer hover:bg-white/5 transition-colors border-l border-white/5"
              onClick={() => identity ? setShowIdentityModal(true) : handleGenerateIdentity()}
            >
              <span className="text-[9px] text-white/30 uppercase font-bold tracking-tighter">Identidad PQC</span>
              <span className={cn(
                "text-[10px] font-medium transition-colors",
                identity ? "text-brand-emerald animate-pulse" : "text-brand-cyan"
              )}>
                {identity ? "Identidad ACTIVA" : "Generar Par"}
              </span>
            </div>
          </div>
        </div>

        {/* Toast de copiado */}
        <AnimatePresence>
          {copiedToast && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 20 }}
              className="fixed bottom-6 right-6 z-50 bg-brand-emerald/90 text-black text-xs font-bold px-5 py-3 rounded-2xl shadow-2xl backdrop-blur-md flex items-center gap-2"
            >
              <CheckCircle2 className="w-4 h-4" />
              Copiado al portapapeles
            </motion.div>
          )}
        </AnimatePresence>

        {/* Identity Modal */}
        <AnimatePresence>
          {showIdentityModal && identity && (
            <div className="fixed inset-0 z-50 flex items-center justify-center p-6 bg-black/60 backdrop-blur-md">
              <motion.div
                initial={{ opacity: 0, scale: 0.9, y: 20 }}
                animate={{ opacity: 1, scale: 1, y: 0 }}
                exit={{ opacity: 0, scale: 0.9, y: 20 }}
                className="w-full max-w-xl bg-zinc-900 border border-white/10 rounded-[32px] overflow-hidden shadow-2xl"
              >
                <div className="p-8 space-y-6 max-h-[90vh] overflow-y-auto custom-scrollbar">
                  <div className="flex justify-between items-start">
                    <div>
                      <h2 className="text-xl font-bold text-white flex items-center gap-2">
                        <Fingerprint className="text-brand-cyan w-5 h-5" /> Tu Identidad Cuántica
                      </h2>
                      <p className="text-xs text-white/40 mt-1">Híbrida: ML-KEM-1024 + ML-DSA-65</p>
                    </div>
                    <div className="flex gap-2">
                      <button
                        onClick={() => setShowKeyGuide(!showKeyGuide)}
                        className={cn(
                          "w-8 h-8 rounded-full flex items-center justify-center transition-all",
                          showKeyGuide ? "bg-brand-cyan text-black" : "bg-white/5 text-white/40 hover:bg-white/10"
                        )}
                        title="¿Cómo usar estas llaves?"
                      >
                        <Info className="w-4 h-4" />
                      </button>
                      <button onClick={() => setShowIdentityModal(false)} className="text-white/20 hover:text-white/60 transition-colors">
                        <XCircle className="w-6 h-6" />
                      </button>
                    </div>
                  </div>

                  <AnimatePresence>
                    {showKeyGuide && (
                      <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: 'auto', opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        className="overflow-hidden"
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
                  </AnimatePresence>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {/* Cifrado KEM */}
                    <div className="space-y-4">
                      <div className="space-y-2">
                        <div className="flex justify-between items-center text-[10px] font-bold text-brand-cyan uppercase tracking-widest px-1">
                          <span>Pública (Cifrado)</span>
                          <button onClick={() => copyToClipboard(identity.kem_pub)} className="hover:text-white transition-colors">Copiar</button>
                        </div>
                        <div className="bg-black/40 border border-white/5 rounded-xl p-3 font-mono text-[8px] break-all leading-tight text-white/60 h-20 overflow-y-auto custom-scrollbar">
                          {identity.kem_pub}
                        </div>
                      </div>
                      <div className="space-y-2">
                        <div className="flex justify-between items-center text-[10px] font-bold text-brand-violet uppercase tracking-widest px-1">
                          <span>Privada (Cifrado)</span>
                          <button onClick={() => copyToClipboard(identity.kem_priv)} className="hover:text-white transition-colors">Copiar</button>
                        </div>
                        <div className="bg-black/40 border border-white/5 rounded-xl p-3 font-mono text-[8px] break-all leading-tight text-white/40 h-20 overflow-y-auto custom-scrollbar">
                          {identity.kem_priv}
                        </div>
                      </div>
                    </div>

                    {/* Firma DSA */}
                    <div className="space-y-4">
                      <div className="space-y-2">
                        <div className="flex justify-between items-center text-[10px] font-bold text-brand-emerald uppercase tracking-widest px-1">
                          <span>Pública (Verificación)</span>
                          <button onClick={() => copyToClipboard(identity.dsa_pub)} className="hover:text-white transition-colors">Copiar</button>
                        </div>
                        <div className="bg-black/40 border border-white/5 rounded-xl p-3 font-mono text-[8px] break-all leading-tight text-white/60 h-20 overflow-y-auto custom-scrollbar">
                          {identity.dsa_pub}
                        </div>
                      </div>
                      <div className="space-y-2">
                        <div className="flex justify-between items-center text-[10px] font-bold text-brand-amber-400 uppercase tracking-widest px-1">
                          <span>Privada (Firma)</span>
                          <button onClick={() => copyToClipboard(identity.dsa_priv)} className="hover:text-white transition-colors">Copiar</button>
                        </div>
                        <div className="bg-black/40 border border-white/5 rounded-xl p-3 font-mono text-[8px] break-all leading-tight text-white/40 h-20 overflow-y-auto custom-scrollbar">
                          {identity.dsa_priv}
                        </div>
                      </div>
                    </div>
                  </div>

                  <div className="bg-white/5 border border-white/10 p-4 rounded-2xl flex gap-3">
                    <ShieldAlert className="w-5 h-5 text-brand-cyan flex-shrink-0" />
                    <p className="text-[10px] text-white/60 leading-snug">
                      <strong>FIPS-204 Standard:</strong> Esta identidad permite cifrado resistente a ordenadores cuánticos y firmas digitales infalsificables. Asegúrate de guardar las 4 llaves en un lugar seguro.
                    </p>
                  </div>

                  <div className="pt-2 flex gap-3">
                    <button 
                      onClick={() => {
                        if(window.confirm("¿Estás seguro? Esto reemplazará tu identidad actual.")) {
                          handleGenerateIdentity();
                        }
                      }}
                      className="flex-1 py-3 bg-white/5 border border-white/10 rounded-2xl text-[10px] font-bold uppercase tracking-widest hover:bg-white/10 transition-all text-white/60"
                    >
                      Regenerar Nueva Identidad
                    </button>
                    <button 
                      onClick={() => {
                        if(window.confirm("¿Eliminar identidad de la memoria?")) {
                          setIdentity(null);
                          setShowIdentityModal(false);
                        }
                      }}
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

        {/* Contacts Modal */}
        <AnimatePresence>
          {showContacts && (
            <div className="fixed inset-0 z-50 flex items-center justify-center p-6 bg-black/60 backdrop-blur-md">
              <motion.div
                initial={{ opacity: 0, scale: 0.9, y: 20 }}
                animate={{ opacity: 1, scale: 1, y: 0 }}
                exit={{ opacity: 0, scale: 0.9, y: 20 }}
                className="w-full max-w-lg bg-zinc-900 border border-white/10 rounded-[32px] overflow-hidden shadow-2xl"
              >
                {!isContactsUnlocked ? (
                  /* Password Prompt for Contacts */
                  <div className="p-8 space-y-6">
                    <div className="text-center space-y-2">
                      <div className="w-16 h-16 bg-brand-cyan/20 rounded-full flex items-center justify-center mx-auto mb-4">
                        <Lock className="text-brand-cyan w-8 h-8" />
                      </div>
                      <h2 className="text-xl font-bold text-white">Libreta Bloqueada</h2>
                      <p className="text-xs text-white/40">Introduce tu contraseña maestra para acceder</p>
                    </div>
                    <div className="space-y-4">
                      <input
                        type="password"
                        placeholder="Contraseña de la bóveda..."
                        value={contactsPassword}
                        onChange={e => setContactsPassword(e.target.value)}
                        onKeyDown={e => e.key === 'Enter' && loadContacts()}
                        className="w-full bg-black/40 border border-white/10 rounded-2xl px-6 py-4 text-center focus:outline-none focus:ring-2 focus:ring-brand-cyan/20"
                      />
                      <div className="flex gap-3">
                        <button 
                          onClick={closeContacts}
                          className="flex-1 py-3 bg-white/5 rounded-2xl text-[10px] font-bold uppercase tracking-widest text-white/40"
                        >
                          Cancelar
                        </button>
                        <button 
                          onClick={() => loadContacts()}
                          className="flex-1 py-3 bg-brand-cyan text-black rounded-2xl text-[10px] font-bold uppercase tracking-widest"
                        >
                          Desbloquear
                        </button>
                      </div>
                    </div>
                  </div>
                ) : (
                  /* Contacts Content (Unlocked) */
                  <div className="p-8 space-y-6">
                    <div className="flex justify-between items-start">
                      <div>
                        <h2 className="text-xl font-bold text-white flex items-center gap-2">
                          <Users className="text-brand-cyan w-5 h-5" /> Libreta de Contactos
                        </h2>
                        <p className="text-xs text-white/40 mt-1">Llaves Públicas Guardadas (Cifrado AES-256)</p>
                      </div>
                      <button onClick={closeContacts} className="text-white/20 hover:text-white/60 transition-colors">
                        <XCircle className="w-6 h-6" />
                      </button>
                    </div>

                    {/* Add Contact Form */}
                    <div className="bg-white/5 border border-white/5 p-4 rounded-2xl space-y-3">
                      <p className="text-[10px] font-bold text-white/40 uppercase tracking-widest px-1">Añadir Nuevo</p>
                      <input
                        type="text"
                        placeholder="Nombre del contacto..."
                        value={newContact.name}
                        onChange={e => setNewContact({ ...newContact, name: e.target.value })}
                        className="w-full bg-black/40 border border-white/5 rounded-xl px-4 py-2 text-xs focus:outline-none focus:ring-1 focus:ring-brand-cyan/40"
                      />
                      <textarea
                        placeholder="Llave pública hexadecimal..."
                        value={newContact.key}
                        onChange={e => setNewContact({ ...newContact, key: e.target.value })}
                        className="w-full h-20 bg-black/40 border border-white/5 rounded-xl px-4 py-2 text-[9px] font-mono focus:outline-none focus:ring-1 focus:ring-brand-cyan/40 resize-none"
                      />
                      <button
                        onClick={handleAddContact}
                        className="w-full py-2 bg-brand-cyan text-black font-bold text-[10px] rounded-xl hover:bg-white transition-colors uppercase tracking-widest"
                      >
                        Guardar Contacto
                      </button>
                    </div>

                    {/* Contacts List */}
                    <div className="space-y-2 max-h-48 overflow-y-auto custom-scrollbar pr-2">
                      {contacts.length === 0 && (
                        <p className="text-center text-xs text-white/20 py-4 italic">No hay contactos guardados</p>
                      )}
                      {contacts.map(c => (
                        <div
                          key={c.name}
                          onClick={() => {
                            navigator.clipboard.writeText(c.public_key);
                            setCopiedContact(c.name);
                            setTimeout(() => setCopiedContact(null), 1500);
                          }}
                          className="flex items-center justify-between p-3 bg-white/[0.02] border border-white/5 rounded-xl group hover:bg-white/5 hover:border-brand-cyan/20 transition-all cursor-pointer"
                          title="Clic para copiar llave pública"
                        >
                          <div className="flex-1 min-w-0 pr-4">
                            <div className="flex items-center gap-2">
                              <p className="text-xs font-bold text-white/80">{c.name}</p>
                              {copiedContact === c.name && (
                                <span className="text-[9px] text-brand-emerald font-bold uppercase tracking-widest">✓ Copiada</span>
                              )}
                            </div>
                            <p className="text-[9px] text-white/20 font-mono truncate">{c.public_key}</p>
                          </div>
                          <button
                            onClick={e => { e.stopPropagation(); handleDeleteContact(c.name); }}
                            className="text-white/10 hover:text-red-400 transition-colors flex-shrink-0"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </motion.div>
            </div>
          )}
        </AnimatePresence>

        {/* Security Guide Modal */}
        <AnimatePresence>
          {showGuide && (
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
                    <button onClick={() => setShowGuide(false)} className="text-white/20 hover:text-white/60 transition-colors">
                      <XCircle className="w-8 h-8" />
                    </button>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    {/* Sección 1: Cifrado en Cascada */}
                    <div className="bg-white/[0.02] border border-white/5 p-6 rounded-[24px] space-y-3">
                      <div className="flex items-center gap-2 text-brand-cyan">
                        <Layers className="w-4 h-4" />
                        <h3 className="text-xs font-bold uppercase tracking-widest">Cifrado Simétrico</h3>
                      </div>
                      <p className="text-[11px] text-white/60 leading-relaxed">
                        Usamos un sistema de <strong>doble capa</strong>: AES-256-GCM y ChaCha20-Poly1305. Cada bloque se cifra dos veces con diferentes algoritmos para garantizar que, si uno falla, el otro proteja tus datos.
                      </p>
                    </div>

                    {/* Sección 2: Quantum Ready */}
                    <div className="bg-white/[0.02] border border-white/5 p-6 rounded-[24px] space-y-3">
                      <div className="flex items-center gap-2 text-brand-violet">
                        <Cpu className="w-4 h-4" />
                        <h3 className="text-xs font-bold uppercase tracking-widest">Post-Quantum</h3>
                      </div>
                      <p className="text-[11px] text-white/60 leading-relaxed">
                        Implementamos <strong>ML-KEM-1024</strong> (Kyber), el estándar de NIST contra ataques de ordenadores cuánticos. Las llaves tradicionales (RSA/ECC) serán vulnerables pronto; CryptoBro ya está protegido.
                      </p>
                    </div>

                    {/* Sección 3: Firmas Digitales */}
                    <div className="bg-white/[0.02] border border-white/5 p-6 rounded-[24px] space-y-3">
                      <div className="flex items-center gap-2 text-brand-emerald">
                        <FileCode2 className="w-4 h-4" />
                        <h3 className="text-xs font-bold uppercase tracking-widest">Firmas ML-DSA</h3>
                      </div>
                      <p className="text-[11px] text-white/60 leading-relaxed">
                        Cada archivo puede ser firmado con <strong>ML-DSA-65</strong> (Dilithium). Esto permite al receptor verificar que el archivo es auténtico y no ha sido modificado por terceros (Anti-Tampering).
                      </p>
                    </div>

                    {/* Sección 4: Esteganografía */}
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

                  {/* Sección Extra: Borrado Seguro */}
                  <div className="bg-red-500/5 border border-red-500/10 p-6 rounded-[24px] flex gap-4 items-center">
                    <Trash2 className="w-10 h-10 text-red-500/40" />
                    <div>
                      <h3 className="text-[10px] font-bold text-red-400 uppercase tracking-widest mb-1">Borrado Seguro (Shredding)</h3>
                      <p className="text-[11px] text-white/50 leading-snug">
                        Al habilitar esta opción, el archivo original se sobrescribe con patrones aleatorios (basado en el estándar Gutmann) antes de ser eliminado, haciendo imposible su recuperación forense.
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

        {/* Subtle Bottom Credits */}
        <p className="text-center mt-6 text-[10px] text-white/10 uppercase font-bold tracking-[0.4em]">
          © Daniel Q. Parra
        </p>
      </motion.div>
    </div>
  );
}

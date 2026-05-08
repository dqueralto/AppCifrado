import { useState, useRef, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open, save, ask } from "@tauri-apps/plugin-dialog";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import {
  Shield,
  Unlock,
  FileText,
  ChevronRight,
  Activity,
  CheckCircle2,
  ShieldAlert,
  Fingerprint,
  Zap,
  Key,
  Users,
  HelpCircle,
  Globe,
  Lock,
} from "lucide-react";
import { motion } from "framer-motion";
import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import type { Identity, Contact, AuthTarget } from "./types";
import { toast } from "./toast";
import { SecurityGuideModal } from "./components/SecurityGuideModal";
import { ReAuthModal } from "./components/ReAuthModal";
import { GatekeeperModal } from "./components/GatekeeperModal";
import { IdentityModal } from "./components/IdentityModal";
import { ContactsModal } from "./components/ContactsModal";

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
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
  const [showInitialWarning, setShowInitialWarning] = useState(true);
  const [showGatekeeper, setShowGatekeeper] = useState(false);
  const [isAppUnlocked, setIsAppUnlocked] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);
  const clipboardTimeoutRef = useRef<number | null>(null);
  const [mode, setMode] = useState<'encrypt' | 'decrypt' | 'stego'>('encrypt');
  const [itemType, setItemType] = useState<'file' | 'folder'>('file');
  const [cryptoMethod, setCryptoMethod] = useState<'password' | 'quantum'>('password');
  const [identity, setIdentity] = useState<Identity | null>(null);
  const [shredOriginal, setShredOriginal] = useState(false);
  const [contacts, setContacts] = useState<Contact[]>([]);
  const [showContacts, setShowContacts] = useState(false);
  const [stegoAction, setStegoAction] = useState<'hide' | 'extract'>('hide');
  const [showGuide, setShowGuide] = useState(false);
  const [showKeyGuide, setShowKeyGuide] = useState(false);
  const [showIdentityModal, setShowIdentityModal] = useState(false);
  const [carrierPath, setCarrierPath] = useState("");
  const [contactsPassword, setContactsPassword] = useState("");
  const [authTarget, setAuthTarget] = useState<AuthTarget>(null);
  const [authInput, setAuthInput] = useState("");
  const [copiedContact, setCopiedContact] = useState<string | null>(null);
  const [isLoadingContacts, setIsLoadingContacts] = useState(false);

  // Seguridad: Zeroize de Master Password por inactividad (15 min)
  useEffect(() => {
    if (!isAppUnlocked) return;

    let lastActivity = Date.now();
    const updateActivity = () => { lastActivity = Date.now(); };

    // Usamos { passive: true } para no bloquear el hilo de renderizado
    window.addEventListener('mousemove', updateActivity, { passive: true });
    window.addEventListener('keydown', updateActivity, { passive: true });

    const interval = setInterval(() => {
      if (Date.now() - lastActivity > 15 * 60 * 1000) {
        setIsAppUnlocked(false);
        setContactsPassword("");
        setShowGatekeeper(true);
      }
    }, 10000); // Comprobación cada 10 segundos

    return () => {
      window.removeEventListener('mousemove', updateActivity);
      window.removeEventListener('keydown', updateActivity);
      clearInterval(interval);
    };
  }, [isAppUnlocked]);

  const closeContacts = () => {
    setShowContacts(false);
    setContacts([]);
  };

  /**
   * Carga la lista de contactos desde el almacenamiento cifrado.
   * Requiere la contraseña maestra para derivar la llave de descifrado AES.
   */
  const loadContacts = async (pass?: string) => {
    const p = pass || contactsPassword;
    if (!p) {
      toast.error("Introduce la contraseña de la libreta");
      return;
    }
    setIsLoadingContacts(true);
    try {
      const list: any = await invoke("get_contacts", { password: p });
      setContacts(list);
    } catch (err) {
      toast.error(String(err));
      setContacts([]);
    } finally {
      setIsLoadingContacts(false);
    }
  };

  /**
   * Añade un nuevo contacto a la libreta cifrada.
   * Realiza un Zeroize implícito de la contraseña tras la operación en el backend.
   */
  const handleAddContact = async (contact: { name: string; key: string; verifierKey: string }) => {
    if (!contact.name || !contact.key || !contactsPassword || isLoadingContacts) return false;
    setIsLoadingContacts(true);
    try {
      await invoke("save_contact", {
        password: contactsPassword,
        name: contact.name,
        publicKey: contact.key,
        verifierKey: contact.verifierKey || ""
      });
      await loadContacts(contactsPassword);
      toast.success("Contacto guardado de forma segura");
      return true;
    } catch (err) {
      toast.error(String(err));
      setIsLoadingContacts(false);
      return false;
    }
  };

  /**
   * Elimina un contacto por su nombre único.
   */
  const handleDeleteContact = async (name: string) => {
    if (isLoadingContacts) return;
    setIsLoadingContacts(true);
    try {
      await invoke("delete_contact", { password: contactsPassword, name });
      await loadContacts(contactsPassword);
      toast.success("Contacto eliminado");
    } catch (err) {
      toast.error(String(err));
      setIsLoadingContacts(false);
    }
  };

  /**
   * Copia texto al portapapeles con fallback para navegadores antiguos
   * y limpieza automática programada.
   */
  const copyToClipboard = async (text: string) => {
    let success = false;
    try {
      await writeText(text);
      success = true;
    } catch (e) {
      try {
        await navigator.clipboard.writeText(text);
        success = true;
      } catch (err2) {
        console.error("Error del Portapapeles:", err2);
      }
    }
    
    if (success) {
      toast.success("Copiado al portapapeles");
    }

    // Limpieza automática del portapapeles tras 10 segundos por seguridad
    if (clipboardTimeoutRef.current) {
      window.clearTimeout(clipboardTimeoutRef.current);
    }
    clipboardTimeoutRef.current = window.setTimeout(async () => {
      try {
        await writeText("");
      } catch (e) {
        navigator.clipboard.writeText("").catch(() => {});
      }
    }, 10000);
  };

  const handleGenerateIdentity = async () => {
    const tid = toast.loading("Generando Identidad Cuántica (ML-KEM + ML-DSA)...");
    try {
      const result: any = await invoke("generate_quantum_keys");
      if (result.success && result.data) {
        const [kp, ks, dp, ds] = result.data.split(":");
        setIdentity({ kem_pub: kp, kem_priv: ks, dsa_pub: dp, dsa_priv: ds });
        setShowKeyGuide(false);
        setShowIdentityModal(true);
        toast.success("Identidad generada con éxito", { id: tid });
      } else {
        toast.error("Fallo al generar la identidad", { id: tid });
      }
    } catch (err: any) {
      toast.error("Error al generar identidad: " + err.toString(), { id: tid });
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
      toast.error("Se requiere archivo/carpeta y llave/contraseña");
      return;
    }

    if (mode === 'stego' && !inputPath) {
      toast.error("Selecciona primero el archivo .vault o la imagen");
      return;
    }

    if (mode === 'decrypt' && cryptoMethod === 'quantum' && !verifierKey) {
      const confirmed = await ask(
        "No has aportado una llave de verificación (Firma Digital) para autenticar este archivo.\n\nEl sistema procederá a descifrarlo, pero no podremos garantizar que el archivo provenga de una fuente legítima o que no haya sido alterado por un tercero.\n\n¿Estás seguro de que deseas proceder a ciegas bajo tu propia responsabilidad?",
        { title: "Advertencia Crítica: Descifrado sin Autenticar", kind: "warning" }
      );
      if (!confirmed) {
        return;
      }
    }

    setIsProcessing(true);

    try {
      let outputPath: string | null = "";

      if (mode === 'stego') {
        if (stegoAction === 'hide') {
          if (!carrierPath) {
            toast.error("Se requiere un archivo de camuflaje");
            setIsProcessing(false);
            return;
          }

          /* 
           * IMPLEMENTACIÓN PQC - PASO 1 (ENCAPSULACIÓN):
           * Se encapsula una clave compartida usando ML-KEM-1024 (FIPS 203).
           * Esto genera un secreto compartido y un texto cifrado que solo el poseedor 
           * de la llave privada correspondiente podrá decapsular.
           * Ejemplo lógico: let (ciphertext, shared_secret) = pk.encapsulate(&mut OsRng);
           *
           * IMPLEMENTACIÓN PQC - PASO 2 (DERIVACIÓN):
           * El secreto compartido de ML-KEM sirve como semilla de entropía para derivar 
           * las llaves simétricas finales (AES-256-GCM + ChaCha20-Poly1305).
           */

          outputPath = await save({
            title: "Guardar archivo camuflado",
            defaultPath: "secreto_oculto",
            filters: [{ name: 'Todos los archivos', extensions: ['*'] }]
          });
          if (!outputPath) {
            setIsProcessing(false);
            return;
          }

          const tid = toast.loading("Ocultando contenedor...");
          const result: any = await invoke("hide_in_image", {
            imagePath: carrierPath,
            vaultPath: inputPath,
            outputPath
          });

          if (result.success) {
            toast.success(result.message, { id: tid });
          } else {
            toast.error(result.message || "Error al ocultar", { id: tid });
          }
        } else {
          // Extraer vault de imagen
          outputPath = await save({
            title: "Guardar contenedor extraído",
            defaultPath: "extraido.vault",
            filters: [{ name: 'Bóveda', extensions: ['vault'] }]
          });
          if (!outputPath) {
            setIsProcessing(false);
            return;
          }

          const tid = toast.loading("Extrayendo contenedor...");
          const result: any = await invoke("extract_from_image", {
            imagePath: inputPath,
            outputVaultPath: outputPath
          });

          if (result.success) {
            toast.success(result.message, { id: tid });
          } else {
            toast.error(result.message || "Error al extraer: No se encontraron datos", { id: tid });
          }
        }
        setIsProcessing(false);
        // Limpiar estados tras la operación para evitar reutilización accidental
        setInputPath("");
        setCarrierPath("");
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
        setIsProcessing(false);
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

      const tid = toast.loading(mode === 'encrypt' ? "Asegurando..." : "Descifrando...");
      
      try {
        const result: any = await invoke(command, args);

        if (result.success) {
          toast.success(result.message, { id: tid });
          setInputPath("");
        } else {
          toast.error("Operación fallida", { id: tid });
        }
      } catch (err: any) {
        toast.error(err.toString(), { id: tid });
      }
    } catch (err: any) {
      toast.error(err.toString());
    } finally {
      setIsProcessing(false);
      // Seguridad Zero-Trust: Destrucción de secretos de la RAM de V8 y DOM 
      // tras cada operación para evitar que queden expuestos si el usuario se ausenta.
      setPassword("");
      setQuantumKey("");
      setVerifierKey("");
    }
  };

  // Eliminamos la duplicación de lógica de Gatekeeper (Bug #11 de auditoría)
  const handleGatekeeperUnlock = async () => {
    if (!contactsPassword) return;
    try {
      await invoke("get_contacts", { password: contactsPassword });
      setIsAppUnlocked(true);
      setShowGatekeeper(false);
      toast.success("Bóveda desbloqueada");
    } catch (err: any) {
      toast.error(err.toString());
    }
  };

  // Eliminamos la duplicación de lógica de Re-Auth (Bug #12 de auditoría)
  const handleReAuthVerify = () => {
    if (authInput === contactsPassword) {
      if (authTarget === 'keys') {
        if (identity) setShowIdentityModal(true);
        else handleGenerateIdentity();
      }
      setAuthTarget(null);
      setAuthInput("");
    } else {
      toast.error("Contraseña incorrecta");
      setAuthInput("");
    }
  };

  return (
    <div className="min-h-screen text-white flex flex-col items-center justify-center p-8 font-sans selection:bg-brand-cyan/30">

      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        className="w-full max-w-lg relative"
      >
        {/* Tarjeta Principal con Efecto Glassmorphism */}
        <div className="bg-black/40 backdrop-blur-3xl border border-white/10 rounded-[32px] shadow-2xl overflow-hidden">

          {/* Sección de Cabecera: Logo y Estado de Identidad */}
          <div className="p-8 pb-0 flex flex-col items-center text-center">
            <div className="w-20 h-20 rounded-3xl bg-gradient-to-br from-brand-cyan/20 to-brand-violet/20 flex items-center justify-center border border-white/10 mb-6 shadow-inner">
              <Shield className="w-10 h-10 text-brand-cyan" />
            </div>
            <h1 className="text-3xl font-bold tracking-tight mb-2">CryptoBro</h1>
            <div className="flex items-center gap-3">
              <div className="flex items-center gap-2 text-xs font-medium text-white/40 uppercase tracking-widest bg-white/5 px-3 py-1 rounded-full border border-white/5">
                <Fingerprint className="w-3 h-3" /> Seguridad Post-Cuántica
              </div>
              <div className="flex items-center gap-4">
                <button
                  onClick={() => setShowGuide(true)}
                  className="text-[10px] font-bold text-white/40 uppercase tracking-tighter hover:text-brand-cyan transition-colors flex items-center gap-1"
                >
                  <HelpCircle className="w-3 h-3" /> Guía
                </button>
                <button
                  onClick={() => { setShowContacts(true); loadContacts(contactsPassword); }}
                  className="text-[10px] font-bold text-white/40 uppercase tracking-tighter hover:text-brand-cyan transition-colors flex items-center gap-1"
                >
                  <Users className="w-3 h-3" /> Contactos
                </button>
                {identity && (
                  <button
                    onClick={() => {
                      setIdentity(null);
                      setQuantumKey("");
                      setVerifierKey("");
                    }}
                    className="text-[10px] font-bold text-brand-emerald/80 uppercase tracking-tighter hover:text-red-400 transition-colors flex items-center gap-1"
                    title="Cerrar Sesión Cuántica"
                  >
                    <Shield className="w-3 h-3" /> Salir (KEM)
                  </button>
                )}
              </div>
            </div>
          </div>

          {/* Mode & Method Selectors */}
          <div className="px-8 mt-10 space-y-4">
            <div className="bg-white/5 p-1 rounded-2xl flex border border-white/10">
              <button
                onClick={() => { setMode('encrypt'); setInputPath(""); }}
                className={cn(
                  "flex-1 py-3 rounded-xl text-sm font-semibold transition-all flex items-center justify-center gap-2",
                  mode === 'encrypt' ? "bg-white/10 text-brand-violet shadow-lg border border-white/10" : "text-white/40 hover:text-white/60"
                )}
              >
                <Lock className="w-4 h-4" /> Cifrar
              </button>
              <button
                onClick={() => { setMode('decrypt'); setInputPath(""); }}
                className={cn(
                  "flex-1 py-3 rounded-xl text-sm font-semibold transition-all flex items-center justify-center gap-2",
                  mode === 'decrypt' ? "bg-white/10 text-brand-emerald shadow-lg border border-white/10" : "text-white/40 hover:text-white/60"
                )}
              >
                <Unlock className="w-4 h-4" /> Descifrar
              </button>
              <button
                onClick={() => { setMode('stego'); setInputPath(""); }}
                className={cn(
                  "flex-1 py-3 rounded-xl text-sm font-semibold transition-all flex items-center justify-center gap-2",
                  mode === 'stego' ? "bg-white/10 text-brand-cyan shadow-lg border border-white/10" : "text-white/40 hover:text-white/60"
                )}
              >
                <Zap className="w-4 h-4" /> Ocultar
              </button>
            </div>

            {mode === 'stego' ? (
              <div className="flex bg-white/5 p-1 rounded-xl border border-white/5">
                <button
                  onClick={() => setStegoAction('hide')}
                  className={cn(
                    "flex-1 py-2 rounded-lg text-[10px] font-bold uppercase tracking-widest transition-all",
                    stegoAction === 'hide' ? "bg-brand-emerald/20 text-brand-emerald" : "text-white/20 hover:text-white/40"
                  )}
                >
                  Ocultar en Imagen
                </button>
                <button
                  onClick={() => setStegoAction('extract')}
                  className={cn(
                    "flex-1 py-2 rounded-lg text-[10px] font-bold uppercase tracking-widest transition-all",
                    stegoAction === 'extract' ? "bg-brand-emerald/20 text-brand-emerald" : "text-white/20 hover:text-white/40"
                  )}
                >
                  Extraer de Imagen
                </button>
              </div>
            ) : (
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
                    onClick={() => { setItemType('folder'); setInputPath(""); }}
                    className={cn(
                      "text-[10px] font-bold uppercase tracking-widest px-3 py-1.5 rounded-lg border transition-all flex items-center gap-2",
                      itemType === 'folder' ? "border-brand-cyan/50 text-brand-cyan bg-brand-cyan/5" : "border-white/5 text-white/20 hover:text-white/40"
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
                    <Key className="w-3 h-3" /> Contraseña
                  </button>
                  <button
                    onClick={() => { setCryptoMethod('quantum'); setInputPath(""); }}
                    className={cn(
                      "text-[10px] font-bold uppercase tracking-widest px-3 py-1.5 rounded-lg border transition-all flex items-center gap-2",
                      cryptoMethod === 'quantum' ? "border-brand-cyan/50 text-brand-cyan bg-brand-cyan/5" : "border-white/5 text-white/20 hover:text-white/40"
                    )}
                  >
                    <Zap className="w-3 h-3" /> PQC
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Área de Interacción Principal */}
          <div className="p-8 space-y-6">

            {/* Zona de Selección de Archivos (Dropzone) */}
            <div className="space-y-4">
              <div className={cn(
                "group relative overflow-hidden rounded-[24px] border-2 border-dashed transition-all duration-500",
                inputPath ? "bg-white/10 border-brand-cyan/50" : "bg-white/5 border-white/5 hover:border-white/10",
                mode === 'stego' && stegoAction === 'extract' && "border-brand-emerald/30"
              )}>
                <button
                  onClick={handleSelectFile}
                  className="w-full p-8 flex flex-col items-center justify-center gap-4 group"
                >
                  <div className={cn(
                    "w-12 h-12 rounded-2xl flex items-center justify-center transition-all duration-500 group-hover:scale-110 shadow-lg",
                    inputPath ? "bg-brand-cyan text-black" : "bg-white/5 text-white/20",
                    mode === 'stego' && stegoAction === 'extract' && "bg-brand-emerald/20 text-brand-emerald"
                  )}>
                    {itemType === 'file' ? <FileText className="w-6 h-6" /> : <Shield className="w-6 h-6" />}
                  </div>
                  <div className="text-center">
                    <p className="text-[11px] font-bold text-white/80 tracking-wide uppercase">
                      {inputPath ? (inputPath.split('/').pop()) : (
                        mode === 'stego'
                          ? (stegoAction === 'hide' ? 'Paso 1: Selecciona el .vault' : 'Selecciona Imagen Camuflada')
                          : `Seleccionar ${itemType === 'file' ? 'Archivo' : 'Carpeta'}`
                      )}
                    </p>
                  </div>
                </button>
              </div>

              {mode === 'stego' && stegoAction === 'hide' && (
                <div className={cn(
                  "group relative overflow-hidden rounded-[24px] border-2 border-dashed transition-all duration-500",
                  carrierPath ? "bg-white/10 border-brand-emerald/50" : "bg-white/5 border-white/5 hover:border-white/10"
                )}>
                  <button
                    onClick={handleSelectCarrier}
                    className="w-full p-8 flex flex-col items-center justify-center gap-4 group"
                  >
                    <div className={cn(
                      "w-12 h-12 rounded-2xl flex items-center justify-center transition-all duration-500 group-hover:scale-110 shadow-lg",
                      carrierPath ? "bg-brand-emerald text-black" : "bg-white/5 text-white/20"
                    )}>
                      <Globe className="w-6 h-6" />
                    </div>
                    <div className="text-center">
                      <p className="text-[11px] font-bold text-white/80 tracking-wide uppercase">
                        {carrierPath ? (carrierPath.split('/').pop()) : 'Paso 2: Selecciona el Archivo de Camuflaje'}
                      </p>
                    </div>
                  </button>
                </div>
              )}
            </div>

            {/* Entrada de Secreto (Contraseña o Llave PQC) */}
            {mode !== 'stego' && (
              <div className="space-y-4">
                <div className="flex justify-between items-center px-1">
                  <span className="text-[10px] font-bold text-white/40 uppercase tracking-widest">
                    {cryptoMethod === 'password' ? 'Contraseña Maestra' : 'Identidad Cuántica (ML-KEM)'}
                  </span>
                  <div className="flex gap-2">
                    {cryptoMethod === 'password' && (
                      <span className="text-[9px] text-brand-emerald font-bold uppercase">Militar-Grade</span>
                    )}
                  </div>
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
                  <div className="space-y-4">
                    <div className="space-y-1">
                      <p className="text-[9px] text-white/20 uppercase px-1">{mode === 'encrypt' ? 'Llave de Cifrado (KEM)' : 'Llave de Descifrado (KEM)'}</p>
                      <textarea
                        value={quantumKey}
                        onChange={(e) => setQuantumKey(e.target.value)}
                        placeholder={mode === 'encrypt' ? "Pega aquí la llave pública hexadecimal..." : "Pega aquí tu llave privada hexadecimal..."}
                        className="w-full h-24 bg-white/5 border border-white/10 rounded-2xl px-6 py-4 focus:outline-none focus:ring-2 focus:ring-brand-cyan/20 transition-all placeholder:text-white/10 text-[10px] leading-tight font-mono resize-none"
                      />
                    </div>

                    {mode === 'decrypt' && (
                      <div className="space-y-1">
                        <p className="text-[9px] text-brand-emerald/40 uppercase px-1 flex items-center gap-1">
                          <CheckCircle2 className="w-2.5 h-2.5" /> Llave de Verificación (ML-DSA) - Opcional
                        </p>
                        <textarea
                          value={verifierKey}
                          onChange={(e) => setVerifierKey(e.target.value)}
                          placeholder="Pega la llave pública del remitente para verificar la integridad..."
                          className="w-full h-16 bg-white/5 border border-white/10 rounded-2xl px-6 py-4 focus:outline-none focus:ring-2 focus:ring-brand-emerald/20 transition-all placeholder:text-white/10 text-[9px] leading-tight font-mono resize-none"
                        />
                      </div>
                    )}

                    {mode === 'encrypt' && contacts.length > 0 && (
                      <div className="flex flex-wrap gap-2">
                        {contacts.map(c => (
                          <button
                            key={c.name}
                            onClick={() => setQuantumKey(c.public_key)}
                            className="text-[9px] px-2 py-1 rounded-md bg-white/5 border border-white/5 hover:border-brand-cyan/30 text-white/40 hover:text-brand-cyan transition-all"
                          >
                            {c.name}
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            {/* Opciones Adicionales (Borrado Seguro) */}
            {mode === 'encrypt' && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="flex items-center justify-between px-4 py-3 bg-white/5 border border-white/10 rounded-2xl"
              >
                <div className="flex items-center gap-3">
                  <div className={cn(
                    "p-2 rounded-lg transition-colors",
                    shredOriginal ? "bg-red-500/20 text-red-400" : "bg-white/5 text-white/20"
                  )}>
                    <ShieldAlert className="w-4 h-4" />
                  </div>
                  <div>
                    <p className="text-[11px] font-bold text-white/60 uppercase tracking-widest">Borrado Seguro</p>
                    <p className="text-[9px] text-white/30 uppercase">Destruir original tras cifrar</p>
                  </div>
                </div>
                <button
                  onClick={() => setShredOriginal(!shredOriginal)}
                  className={cn(
                    "w-12 h-6 rounded-full relative transition-all duration-300",
                    shredOriginal ? "bg-red-500" : "bg-white/10"
                  )}
                >
                  <motion.div
                    animate={{ x: shredOriginal ? 24 : 4 }}
                    className="absolute top-1 left-0 w-4 h-4 bg-white rounded-full shadow-lg"
                  />
                </button>
              </motion.div>
            )}

            {/* Botón de Ejecución Maestro */}
            <div className="pt-2">
              <button
                disabled={
                  isProcessing ||
                  (!inputPath) ||
                  (mode !== 'stego' && cryptoMethod === 'password' && !password) ||
                  (mode !== 'stego' && cryptoMethod === 'quantum' && !quantumKey) ||
                  (mode === 'stego' && stegoAction === 'hide' && !carrierPath)
                }
                onClick={runOperation}
                className={cn(
                  "w-full h-16 rounded-2xl font-bold text-lg flex items-center justify-center gap-3 transition-all relative overflow-hidden group",
                  mode === 'encrypt'
                    ? "bg-brand-violet text-white"
                    : mode === 'decrypt'
                      ? "bg-brand-emerald text-black"
                      : "bg-brand-cyan text-black",
                  isProcessing && "opacity-50 cursor-wait"
                )}
              >
                {isProcessing ? (
                  <div className="flex flex-col items-center gap-1 w-full px-6">
                    <div className="flex items-center gap-3">
                      <Activity className="w-5 h-5 animate-spin" />
                      <span className="tracking-[0.2em]">PROCESANDO...</span>
                    </div>
                    {/* Progress Bar Indeterminada */}
                    <div className="w-full h-1 bg-black/40 rounded-full overflow-hidden relative mt-1">
                      <motion.div 
                        initial={{ x: '-100%' }}
                        animate={{ x: '100%' }}
                        transition={{ repeat: Infinity, duration: 1.5, ease: 'linear' }}
                        className="w-1/2 h-full bg-white/80 rounded-full"
                      />
                    </div>
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
                  mode === 'encrypt' ? "bg-brand-cyan" : mode === 'decrypt' ? "bg-white" : "bg-white"
                )} />
              </button>
            </div>
          </div>

          {/* Barras de Información del Pie (Métodos Activos) */}
          <div className="flex border-t border-white/5 divide-x divide-white/5 bg-white/[0.02]">
            <div className="flex-1 p-4 flex flex-col items-center">
              <span className="text-[9px] text-white/30 uppercase font-bold tracking-tighter">Cifrado</span>
              <span className="text-[10px] font-medium text-white/60">AES+ChaCha20</span>
            </div>
            <div
              className="flex-1 p-4 flex flex-col items-center group cursor-pointer hover:bg-white/5 transition-colors border-l border-white/5"
              onClick={() => { setAuthTarget('keys'); setAuthInput(""); }}
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



        <IdentityModal
          show={showIdentityModal}
          identity={identity}
          showKeyGuide={showKeyGuide}
          onClose={() => setShowIdentityModal(false)}
          onToggleGuide={() => setShowKeyGuide(v => !v)}
          onCopyKey={copyToClipboard}
          onRegenerate={handleGenerateIdentity}
          onDelete={() => { setIdentity(null); setShowIdentityModal(false); }}
        />

        <ContactsModal
          show={showContacts}
          contacts={contacts}
          copiedContact={copiedContact}
          isLoading={isLoadingContacts}
          onClose={closeContacts}
          onAddContact={handleAddContact}
          onDeleteContact={handleDeleteContact}
          onCopyKey={async (text, contactId) => {
            await copyToClipboard(text);
            setCopiedContact(contactId);
            setTimeout(() => setCopiedContact(null), 1500);
          }}
        />

        <SecurityGuideModal show={showGuide} onClose={() => setShowGuide(false)} />

        <ReAuthModal
          authTarget={authTarget}
          authInput={authInput}
          onAuthInputChange={setAuthInput}
          onVerify={handleReAuthVerify}
          onCancel={() => { setAuthTarget(null); setAuthInput(""); }}
        />

        <GatekeeperModal
          showInitialWarning={showInitialWarning}
          showGatekeeper={showGatekeeper}
          isAppUnlocked={isAppUnlocked}
          contactsPassword={contactsPassword}
          onContactsPasswordChange={setContactsPassword}
          onWarningAccepted={() => { setShowInitialWarning(false); setShowGatekeeper(true); }}
          onUnlock={handleGatekeeperUnlock}
        />



        {/* Créditos Sutiles */}
        <p className="text-center mt-6 text-[10px] text-white/10 uppercase font-bold tracking-[0.4em]">
          © Daniel Q. Parra
        </p>
      </motion.div>
    </div>
  );
}

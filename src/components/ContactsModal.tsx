import { motion, AnimatePresence } from "framer-motion";
import { useState } from "react";
import { ask } from "@tauri-apps/plugin-dialog";
import { save } from "@tauri-apps/plugin-dialog";
import { writeFile } from "@tauri-apps/plugin-fs";
import {
  XCircle,
  Users,
  Trash2,
  UserPlus,
  Download,
  QrCode,
  ChevronLeft,
  ArrowDownToLine,
} from "lucide-react";
import { cn } from "../utils";
import { toast } from "../toast";
import { Contact, ContactExportFile } from "../types";
import { QRCodeDisplay } from "./QRCodeDisplay";
import { QRImporter } from "./QRImporter";

type Tab = "list" | "add" | "import";

interface ContactsModalProps {
  show: boolean;
  contacts: Contact[];
  copiedContact: string | null;
  isLoading?: boolean;
  onClose: () => void;
  onAddContact: (contact: { name: string; key: string; verifierKey: string }) => Promise<boolean | void>;
  onDeleteContact: (name: string) => void;
  onCopyKey: (text: string, contactId: string) => void;
}

export function ContactsModal({
  show,
  contacts,
  copiedContact,
  isLoading = false,
  onClose,
  onAddContact,
  onDeleteContact,
  onCopyKey,
}: ContactsModalProps) {
  const [activeTab, setActiveTab] = useState<Tab>("list");
  const [newContact, setNewContact] = useState({ name: "", key: "", verifierKey: "" });
  const [selectedContact, setSelectedContact] = useState<Contact | null>(null);

  // Guardar un nuevo contacto (desde formulario manual o desde importación)
  const handleSave = async () => {
    const success = await onAddContact(newContact);
    if (success) {
      setNewContact({ name: "", key: "", verifierKey: "" });
      setActiveTab("list");
    }
  };

  // Callback del QRImporter: autocompleta el formulario y guarda
  const handleImportPayload = async (name: string, kemKey: string, dsaKey: string) => {
    const success = await onAddContact({ name, key: kemKey, verifierKey: dsaKey });
    if (success) {
      setActiveTab("list");
    }
  };

  // Exportar un contacto como archivo .cbrokey
  const handleExportContact = async (contact: Contact) => {
    const outputPath = await save({
      title: "Exportar identidad de contacto",
      defaultPath: `${contact.name}.cbrokey`,
      filters: [{ name: "Identidad CryptoBro", extensions: ["cbrokey"] }],
    });
    if (!outputPath) return;

    const exportData: ContactExportFile = {
      app: "CryptoBro",
      v: 1,
      name: contact.name,
      kem_pub: contact.public_key,
      dsa_pub: contact.verifier_key || "",
    };

    try {
      const json = JSON.stringify(exportData, null, 2);
      await writeFile(outputPath, new TextEncoder().encode(json));
      toast.success(`Identidad de "${contact.name}" exportada como .cbrokey`);
    } catch (err) {
      toast.error("Error al exportar: " + String(err));
    }
  };

  // Resetear estado al cerrar
  const handleClose = () => {
    setSelectedContact(null);
    setActiveTab("list");
    onClose();
  };

  return (
    <AnimatePresence>
      {show && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-6 bg-black/60 backdrop-blur-md">
          <motion.div
            initial={{ opacity: 0, scale: 0.9, y: 20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.9, y: 20 }}
            className="w-full max-w-lg bg-zinc-900 border border-white/10 rounded-[32px] overflow-hidden shadow-2xl"
          >
            <div className="p-8 space-y-6 max-h-[85vh] overflow-y-auto custom-scrollbar">
              {/* Cabecera del Modal */}
              <div className="flex justify-between items-start">
                <div>
                  <h2 className="text-xl font-bold text-white flex items-center gap-2">
                    <Users className="text-brand-cyan w-5 h-5" /> Libreta de Contactos
                  </h2>
                  <p className="text-xs text-white/40 mt-1">Llaves Públicas Guardadas (Cifrado AES-256)</p>
                </div>
                <button onClick={handleClose} className="text-white/20 hover:text-white/60 transition-colors">
                  <XCircle className="w-6 h-6" />
                </button>
              </div>

              {/* Pestañas de Navegación */}
              {!selectedContact && (
                <div className="flex bg-white/5 p-1 rounded-xl border border-white/5">
                  <button
                    onClick={() => setActiveTab("list")}
                    className={cn(
                      "flex-1 py-2 rounded-lg text-[10px] font-bold uppercase tracking-widest transition-all flex items-center justify-center gap-1.5",
                      activeTab === "list"
                        ? "bg-white/10 text-brand-cyan"
                        : "text-white/30 hover:text-white/50"
                    )}
                  >
                    <Users className="w-3 h-3" /> Contactos
                  </button>
                  <button
                    onClick={() => setActiveTab("add")}
                    className={cn(
                      "flex-1 py-2 rounded-lg text-[10px] font-bold uppercase tracking-widest transition-all flex items-center justify-center gap-1.5",
                      activeTab === "add"
                        ? "bg-white/10 text-brand-emerald"
                        : "text-white/30 hover:text-white/50"
                    )}
                  >
                    <UserPlus className="w-3 h-3" /> Añadir
                  </button>
                  <button
                    onClick={() => setActiveTab("import")}
                    className={cn(
                      "flex-1 py-2 rounded-lg text-[10px] font-bold uppercase tracking-widest transition-all flex items-center justify-center gap-1.5",
                      activeTab === "import"
                        ? "bg-white/10 text-brand-violet"
                        : "text-white/30 hover:text-white/50"
                    )}
                  >
                    <QrCode className="w-3 h-3" /> Importar
                  </button>
                </div>
              )}

              {/* ============================================ */}
              {/* VISTA DE DETALLE DE UN CONTACTO (QR codes) */}
              {/* ============================================ */}
              {selectedContact ? (
                <motion.div
                  initial={{ opacity: 0, x: 20 }}
                  animate={{ opacity: 1, x: 0 }}
                  className="space-y-5"
                >
                  {/* Botón volver */}
                  <button
                    onClick={() => setSelectedContact(null)}
                    className="flex items-center gap-2 text-xs text-white/40 hover:text-white/70 transition-colors"
                  >
                    <ChevronLeft className="w-4 h-4" /> Volver a la lista
                  </button>

                  {/* Nombre del contacto */}
                  <div className="text-center">
                    <div className="w-14 h-14 rounded-2xl bg-brand-cyan/10 border border-brand-cyan/20 flex items-center justify-center mx-auto mb-3">
                      <span className="text-2xl font-bold text-brand-cyan">
                        {selectedContact.name.charAt(0).toUpperCase()}
                      </span>
                    </div>
                    <h3 className="text-lg font-bold text-white">{selectedContact.name}</h3>
                    <p className="text-[10px] text-white/30 uppercase tracking-widest mt-1">
                      Identidad Post-Cuántica
                    </p>
                  </div>

                  {/* QR Codes del contacto */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <QRCodeDisplay
                      name={selectedContact.name}
                      keyHex={selectedContact.public_key}
                      type="kem"
                      size={160}
                    />
                    {selectedContact.verifier_key && (
                      <QRCodeDisplay
                        name={selectedContact.name}
                        keyHex={selectedContact.verifier_key}
                        type="dsa"
                        size={160}
                      />
                    )}
                  </div>

                  {/* Llaves copiables (texto) */}
                  <div className="space-y-2">
                    <div
                      onClick={() => onCopyKey(selectedContact.public_key, `${selectedContact.name}-kem`)}
                      className="flex items-center gap-2 cursor-pointer hover:bg-white/5 p-2 rounded-xl transition-colors border border-white/5"
                      title="Clic para copiar llave KEM"
                    >
                      <span className="text-[9px] font-bold text-brand-cyan/60 shrink-0">[KEM]</span>
                      <p className="text-[8px] text-white/40 font-mono truncate flex-1">
                        {selectedContact.public_key}
                      </p>
                      {copiedContact === `${selectedContact.name}-kem` && (
                        <span className="text-[9px] text-brand-emerald font-bold shrink-0">✓</span>
                      )}
                    </div>
                    {selectedContact.verifier_key && (
                      <div
                        onClick={() => onCopyKey(selectedContact.verifier_key, `${selectedContact.name}-dsa`)}
                        className="flex items-center gap-2 cursor-pointer hover:bg-white/5 p-2 rounded-xl transition-colors border border-white/5"
                        title="Clic para copiar llave DSA"
                      >
                        <span className="text-[9px] font-bold text-brand-emerald/60 shrink-0">[DSA]</span>
                        <p className="text-[8px] text-white/40 font-mono truncate flex-1">
                          {selectedContact.verifier_key}
                        </p>
                        {copiedContact === `${selectedContact.name}-dsa` && (
                          <span className="text-[9px] text-brand-emerald font-bold shrink-0">✓</span>
                        )}
                      </div>
                    )}
                  </div>

                  {/* Acciones del contacto */}
                  <div className="flex gap-2">
                    <button
                      onClick={() => handleExportContact(selectedContact)}
                      className="flex-1 py-2.5 bg-brand-cyan/10 border border-brand-cyan/20 rounded-xl text-[10px] font-bold uppercase tracking-widest text-brand-cyan hover:bg-brand-cyan/20 transition-all flex items-center justify-center gap-2"
                    >
                      <Download className="w-3 h-3" /> Exportar .cbrokey
                    </button>
                    <button
                      onClick={async () => {
                        const ok = await ask(`¿Eliminar el contacto "${selectedContact.name}"?`, {
                          title: "Eliminar Contacto",
                          kind: "warning",
                        });
                        if (ok) {
                          onDeleteContact(selectedContact.name);
                          setSelectedContact(null);
                        }
                      }}
                      className="px-4 py-2.5 bg-red-500/10 border border-red-500/20 rounded-xl text-[10px] font-bold uppercase tracking-widest text-red-400 hover:bg-red-500/20 transition-all"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </motion.div>
              ) : (
                <>
                  {/* ============================================ */}
                  {/* PESTAÑA: LISTA DE CONTACTOS */}
                  {/* ============================================ */}
                  {activeTab === "list" && (
                    <div className="space-y-2 max-h-60 overflow-y-auto custom-scrollbar pr-1">
                      {contacts.length === 0 ? (
                        <div className="text-center py-8 space-y-3">
                          <Users className="w-10 h-10 text-white/10 mx-auto" />
                          <p className="text-xs text-white/20 italic">No hay contactos guardados</p>
                          <p className="text-[9px] text-white/15">
                            Usa las pestañas "Añadir" o "Importar" para agregar contactos
                          </p>
                        </div>
                      ) : (
                        contacts.map((c) => (
                          <motion.div
                            key={c.name}
                            initial={{ opacity: 0, y: 5 }}
                            animate={{ opacity: 1, y: 0 }}
                            className="flex items-center gap-3 p-3 bg-white/[0.02] border border-white/5 rounded-xl cursor-pointer hover:border-brand-cyan/20 hover:bg-white/[0.04] transition-all group"
                            onClick={() => setSelectedContact(c)}
                          >
                            {/* Avatar con inicial */}
                            <div className="w-10 h-10 rounded-xl bg-brand-cyan/10 border border-brand-cyan/20 flex items-center justify-center shrink-0">
                              <span className="text-sm font-bold text-brand-cyan">
                                {c.name.charAt(0).toUpperCase()}
                              </span>
                            </div>

                            {/* Info del contacto */}
                            <div className="flex-1 min-w-0">
                              <p className="text-xs font-bold text-white/80">{c.name}</p>
                              <div className="flex items-center gap-2 mt-0.5">
                                <span className="text-[8px] text-brand-cyan/50 font-mono truncate">
                                  KEM: {c.public_key.substring(0, 24)}...
                                </span>
                                {c.verifier_key && (
                                  <span className="text-[8px] text-brand-emerald/40 font-bold">+ DSA</span>
                                )}
                              </div>
                            </div>

                            {/* Indicador de QR disponible */}
                            <QrCode className="w-4 h-4 text-white/10 group-hover:text-brand-cyan/40 transition-colors shrink-0" />
                          </motion.div>
                        ))
                      )}
                    </div>
                  )}

                  {/* ============================================ */}
                  {/* PESTAÑA: AÑADIR MANUALMENTE */}
                  {/* ============================================ */}
                  {activeTab === "add" && (
                    <div className="space-y-3">
                      <p className="text-[10px] font-bold text-white/40 uppercase tracking-widest px-1">
                        Añadir Manualmente
                      </p>
                      <input
                        type="text"
                        placeholder="Nombre del contacto..."
                        value={newContact.name}
                        onChange={(e) => setNewContact((prev) => ({ ...prev, name: e.target.value }))}
                        className="w-full bg-black/40 border border-white/5 rounded-xl px-4 py-2.5 text-xs focus:outline-none focus:ring-1 focus:ring-brand-cyan/40"
                      />
                      <textarea
                        placeholder="Llave pública de cifrado (ML-KEM)..."
                        value={newContact.key}
                        onChange={(e) => setNewContact((prev) => ({ ...prev, key: e.target.value }))}
                        className="w-full h-20 bg-black/40 border border-white/5 rounded-xl px-4 py-2.5 text-[9px] font-mono focus:outline-none focus:ring-1 focus:ring-brand-cyan/40 resize-none"
                      />
                      <textarea
                        placeholder="Llave pública de verificación (ML-DSA) — Opcional..."
                        value={newContact.verifierKey}
                        onChange={(e) => setNewContact((prev) => ({ ...prev, verifierKey: e.target.value }))}
                        className="w-full h-20 bg-black/40 border border-white/5 rounded-xl px-4 py-2.5 text-[9px] font-mono focus:outline-none focus:ring-1 focus:ring-brand-emerald/40 resize-none"
                      />
                      <button
                        onClick={handleSave}
                        disabled={!newContact.name || !newContact.key || isLoading}
                        className="w-full py-2.5 bg-brand-cyan text-black font-bold text-[10px] rounded-xl hover:bg-white transition-colors uppercase tracking-widest disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                      >
                        {isLoading ? (
                          <>
                            <span className="w-3 h-3 border-2 border-black/40 border-t-black rounded-full animate-spin" />
                            Guardando...
                          </>
                        ) : (
                          <>
                            <ArrowDownToLine className="w-3.5 h-3.5" /> Guardar Contacto
                          </>
                        )}
                      </button>
                    </div>
                  )}

                  {/* ============================================ */}
                  {/* PESTAÑA: IMPORTAR (QR / ARCHIVO) */}
                  {/* ============================================ */}
                  {activeTab === "import" && (
                    <QRImporter onImportPayload={handleImportPayload} />
                  )}
                </>
              )}
            </div>
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  );
}

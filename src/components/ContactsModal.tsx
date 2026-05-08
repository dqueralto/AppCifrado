import { motion, AnimatePresence } from "framer-motion";
import { useState } from "react";
import { ask } from "@tauri-apps/plugin-dialog";
import {
  XCircle,
  Users,
  Trash2,
} from "lucide-react";
import { Contact } from "../types";

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
  const [newContact, setNewContact] = useState({ name: "", key: "", verifierKey: "" });

  const handleSave = async () => {
    const success = await onAddContact(newContact);
    if (success) {
      setNewContact({ name: "", key: "", verifierKey: "" });
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
            className="w-full max-w-lg bg-zinc-900 border border-white/10 rounded-[32px] overflow-hidden shadow-2xl"
          >
            <div className="p-8 space-y-6">
              {/* Cabecera del Modal */}
              <div className="flex justify-between items-start">
                <div>
                  <h2 className="text-xl font-bold text-white flex items-center gap-2">
                    <Users className="text-brand-cyan w-5 h-5" /> Libreta de Contactos
                  </h2>
                  <p className="text-xs text-white/40 mt-1">Llaves Públicas Guardadas (Cifrado AES-256)</p>
                </div>
                <button onClick={onClose} className="text-white/20 hover:text-white/60 transition-colors">
                  <XCircle className="w-6 h-6" />
                </button>
              </div>

              {/* Formulario para Añadir Contacto */}
              <div className="bg-white/5 border border-white/5 p-4 rounded-2xl space-y-3">
                <p className="text-[10px] font-bold text-white/40 uppercase tracking-widest px-1">Añadir Nuevo</p>
                <input
                  type="text"
                  placeholder="Nombre del contacto..."
                  value={newContact.name}
                  onChange={e => setNewContact(prev => ({ ...prev, name: e.target.value }))}
                  className="w-full bg-black/40 border border-white/5 rounded-xl px-4 py-2 text-xs focus:outline-none focus:ring-1 focus:ring-brand-cyan/40"
                />
                <textarea
                  placeholder="Llave pública de cifrado (ML-KEM)..."
                  value={newContact.key}
                  onChange={e => setNewContact(prev => ({ ...prev, key: e.target.value }))}
                  className="w-full h-16 bg-black/40 border border-white/5 rounded-xl px-4 py-2 text-[9px] font-mono focus:outline-none focus:ring-1 focus:ring-brand-cyan/40 resize-none"
                />
                <textarea
                  placeholder="Llave pública de verificación (ML-DSA) (Opcional)..."
                  value={newContact.verifierKey}
                  onChange={e => setNewContact(prev => ({ ...prev, verifierKey: e.target.value }))}
                  className="w-full h-16 bg-black/40 border border-white/5 rounded-xl px-4 py-2 text-[9px] font-mono focus:outline-none focus:ring-1 focus:ring-brand-emerald/40 resize-none"
                />
                <button
                  onClick={handleSave}
                  disabled={!newContact.name || !newContact.key || isLoading}
                  className="w-full py-2 bg-brand-cyan text-black font-bold text-[10px] rounded-xl hover:bg-white transition-colors uppercase tracking-widest disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                >
                  {isLoading ? (
                    <>
                      <span className="w-3 h-3 border-2 border-black/40 border-t-black rounded-full animate-spin" />
                      Guardando...
                    </>
                  ) : 'Guardar Contacto'}
                </button>
              </div>

              {/* Lista de Contactos Guardados */}
              <div className="space-y-2 max-h-52 overflow-y-auto custom-scrollbar pr-2">
                {contacts.length === 0 && (
                  <p className="text-center text-xs text-white/20 py-4 italic">No hay contactos guardados</p>
                )}
                {contacts.map(c => (
                  <div
                    key={c.name}
                    className="flex items-center justify-between p-3 bg-white/[0.02] border border-white/5 rounded-xl group transition-all"
                  >
                    <div className="flex-1 min-w-0 pr-4">
                      <div className="flex items-center gap-2 mb-2">
                        <p className="text-xs font-bold text-white/80">{c.name}</p>
                      </div>
                      <div className="space-y-1">
                        {/* KEM key */}
                        <div
                          onClick={() => onCopyKey(c.public_key, `${c.name}-kem`)}
                          className="flex items-center gap-2 cursor-pointer hover:bg-white/5 p-1 -ml-1 rounded transition-colors"
                          title="Clic para copiar llave KEM"
                        >
                          <p className="text-[9px] text-brand-cyan/50 font-mono truncate flex-1">
                            <span className="text-white/40 mr-1">[KEM]</span>{c.public_key}
                          </p>
                          {copiedContact === `${c.name}-kem` && (
                            <span className="text-[9px] text-brand-emerald font-bold uppercase tracking-widest flex-shrink-0">✓ Copiada</span>
                          )}
                        </div>

                        {/* DSA key (optional) */}
                        {c.verifier_key && (
                          <div
                            onClick={() => onCopyKey(c.verifier_key, `${c.name}-dsa`)}
                            className="flex items-center gap-2 cursor-pointer hover:bg-white/5 p-1 -ml-1 rounded transition-colors"
                            title="Clic para copiar llave DSA"
                          >
                            <p className="text-[9px] text-brand-emerald/50 font-mono truncate flex-1">
                              <span className="text-white/40 mr-1">[DSA]</span>{c.verifier_key}
                            </p>
                            {copiedContact === `${c.name}-dsa` && (
                              <span className="text-[9px] text-brand-emerald font-bold uppercase tracking-widest flex-shrink-0">✓ Copiada</span>
                            )}
                          </div>
                        )}
                      </div>
                    </div>
                    <button
                      onClick={async (e) => {
                        e.stopPropagation();
                        const ok = await ask(`¿Eliminar el contacto "${c.name}"?`, { title: "Eliminar Contacto", kind: "warning" });
                        if (ok) onDeleteContact(c.name);
                      }}
                      className="text-white/10 hover:text-red-400 transition-colors flex-shrink-0"
                      title="Eliminar Contacto"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                ))}
              </div>
            </div>
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  );
}

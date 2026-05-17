import { useState, useRef } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { readFile } from "@tauri-apps/plugin-fs";
import { Upload, FileText, QrCode, Loader2 } from "lucide-react";
import jsQR from "jsqr";
import { cn } from "../utils";
import { toast } from "../toast";
import type { ContactExportFile } from "../types";

interface QRImporterProps {
  onImportPayload: (name: string, kemKey: string, dsaKey: string) => void;
}

/**
 * Convierte una cadena base64 de vuelta a hexadecimal.
 * Es la operación inversa de hexToBase64() en QRCodeDisplay.
 */
function base64ToHex(b64: string): string {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Componente para importar llaves PQC desde:
 * 1. Imagen con QR code (foto/screenshot) → decodificación con jsQR
 * 2. Archivo .cbrokey (JSON con ambas llaves públicas en hex)
 */
export function QRImporter({ onImportPayload }: QRImporterProps) {
  const [isProcessing, setIsProcessing] = useState(false);
  // Almacena temporalmente una llave parcial cuando se importa un solo QR
  const pendingRef = useRef<{ name: string; kem?: string; dsa?: string }>({ name: "" });

  /**
   * Valida que un payload JSON sea un QR compacto legítimo de CryptoBro.
   * Formato compacto: {"a":"CB","v":1,"t":"kem","n":"Nombre","k":"base64..."}
   */
  const validateQRPayload = (data: any): boolean => {
    return (
      data &&
      data.a === "CB" &&
      data.v === 1 &&
      (data.t === "kem" || data.t === "dsa") &&
      typeof data.n === "string" &&
      data.n.length > 0 &&
      typeof data.k === "string" &&
      data.k.length > 0
    );
  };

  /**
   * Valida que un archivo JSON sea un ContactExportFile legítimo de CryptoBro.
   */
  const validateExportFile = (data: any): data is ContactExportFile => {
    return (
      data &&
      data.app === "CryptoBro" &&
      data.v === 1 &&
      typeof data.name === "string" &&
      data.name.length > 0 &&
      typeof data.kem_pub === "string" &&
      data.kem_pub.length > 0
    );
  };

  /**
   * Importar desde una imagen que contiene un QR code.
   * Usa Canvas API para extraer los píxeles y jsQR para decodificar.
   */
  const handleImportQRImage = async () => {
    const selected = await open({
      multiple: false,
      title: "Selecciona una imagen con un QR de CryptoBro",
      filters: [{ name: "Imágenes", extensions: ["png", "jpg", "jpeg", "webp", "bmp"] }],
    });
    if (!selected) return;

    setIsProcessing(true);
    try {
      // Leer la imagen como bytes desde el filesystem nativo de Tauri
      const fileBytes = await readFile(selected as string);
      const blob = new Blob([fileBytes]);
      const url = URL.createObjectURL(blob);

      // Cargar la imagen en un elemento HTML para extraer píxeles
      const img = new Image();
      img.src = url;
      await new Promise<void>((resolve, reject) => {
        img.onload = () => resolve();
        img.onerror = () => reject(new Error("No se pudo cargar la imagen"));
      });

      // Renderizar en un Canvas invisible para obtener los datos de píxeles
      const canvas = document.createElement("canvas");
      canvas.width = img.width;
      canvas.height = img.height;
      const ctx = canvas.getContext("2d");
      if (!ctx) throw new Error("No se pudo crear el contexto Canvas");

      ctx.drawImage(img, 0, 0);
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      URL.revokeObjectURL(url);

      // Decodificar el QR code de los píxeles usando jsQR
      const qrResult = jsQR(imageData.data, imageData.width, imageData.height);
      if (!qrResult) {
        toast.error("No se detectó ningún QR code en la imagen");
        return;
      }

      // Parsear y validar el payload JSON del QR
      let payload: any;
      try {
        payload = JSON.parse(qrResult.data);
      } catch {
        toast.error("El QR no contiene datos válidos de CryptoBro");
        return;
      }

      if (!validateQRPayload(payload)) {
        toast.error("El QR no pertenece a CryptoBro o tiene un formato inválido");
        return;
      }

      // Decodificar la llave de base64 a hex
      const keyHex = base64ToHex(payload.k);
      const contactName = payload.n;
      const keyType = payload.t as "kem" | "dsa";

      // Gestionar la importación parcial (puede requerir 2 QR codes)
      const pending = pendingRef.current;

      if (pending.name && pending.name !== contactName) {
        // Si hay un pendiente de otro contacto, descartarlo y empezar de nuevo
        pendingRef.current = { name: contactName };
      }

      if (keyType === "kem") {
        pendingRef.current = { ...pendingRef.current, name: contactName, kem: keyHex };
      } else {
        pendingRef.current = { ...pendingRef.current, name: contactName, dsa: keyHex };
      }

      const current = pendingRef.current;

      if (current.kem) {
        // Si ya tenemos la llave KEM, podemos importar (DSA es opcional)
        onImportPayload(current.name, current.kem, current.dsa || "");
        pendingRef.current = { name: "" };
        toast.success(`Contacto "${current.name}" importado desde QR`);
      } else {
        // Solo tenemos DSA, necesitamos el QR de KEM
        toast.info(`Llave DSA de "${contactName}" capturada. Ahora importa el QR de Cifrado (KEM)`);
      }
    } catch (err) {
      toast.error("Error al procesar la imagen: " + String(err));
    } finally {
      setIsProcessing(false);
    }
  };

  /**
   * Importar desde un archivo .cbrokey (JSON con ambas llaves en hex).
   */
  const handleImportFile = async () => {
    const selected = await open({
      multiple: false,
      title: "Selecciona un archivo de identidad CryptoBro",
      filters: [{ name: "Identidad CryptoBro", extensions: ["cbrokey", "json"] }],
    });
    if (!selected) return;

    setIsProcessing(true);
    try {
      const fileBytes = await readFile(selected as string);
      const text = new TextDecoder().decode(fileBytes);

      let data: any;
      try {
        data = JSON.parse(text);
      } catch {
        toast.error("El archivo no contiene JSON válido");
        return;
      }

      if (!validateExportFile(data)) {
        toast.error("El archivo no es un .cbrokey válido de CryptoBro");
        return;
      }

      onImportPayload(data.name, data.kem_pub, data.dsa_pub || "");
      toast.success(`Contacto "${data.name}" importado desde archivo`);
    } catch (err) {
      toast.error("Error al leer el archivo: " + String(err));
    } finally {
      setIsProcessing(false);
    }
  };

  return (
    <div className="space-y-3">
      <p className="text-[10px] font-bold text-white/40 uppercase tracking-widest px-1">
        Importar Contacto
      </p>

      {/* Botón: Importar desde imagen QR */}
      <button
        onClick={handleImportQRImage}
        disabled={isProcessing}
        className={cn(
          "w-full flex items-center gap-4 p-4 rounded-2xl border border-white/10 bg-white/[0.02] transition-all group",
          "hover:border-brand-cyan/30 hover:bg-brand-cyan/5",
          isProcessing && "opacity-50 cursor-wait"
        )}
      >
        <div className="p-3 rounded-xl bg-brand-cyan/10 text-brand-cyan group-hover:scale-110 transition-transform">
          {isProcessing ? <Loader2 className="w-5 h-5 animate-spin" /> : <QrCode className="w-5 h-5" />}
        </div>
        <div className="text-left">
          <p className="text-xs font-bold text-white/80">Escanear QR desde Imagen</p>
          <p className="text-[9px] text-white/30">Selecciona una foto o screenshot de un QR code</p>
        </div>
        <Upload className="w-4 h-4 text-white/20 ml-auto" />
      </button>

      {/* Botón: Importar desde archivo .cbrokey */}
      <button
        onClick={handleImportFile}
        disabled={isProcessing}
        className={cn(
          "w-full flex items-center gap-4 p-4 rounded-2xl border border-white/10 bg-white/[0.02] transition-all group",
          "hover:border-brand-emerald/30 hover:bg-brand-emerald/5",
          isProcessing && "opacity-50 cursor-wait"
        )}
      >
        <div className="p-3 rounded-xl bg-brand-emerald/10 text-brand-emerald group-hover:scale-110 transition-transform">
          <FileText className="w-5 h-5" />
        </div>
        <div className="text-left">
          <p className="text-xs font-bold text-white/80">Importar archivo .cbrokey</p>
          <p className="text-[9px] text-white/30">Archivo de identidad CryptoBro con ambas llaves</p>
        </div>
        <Upload className="w-4 h-4 text-white/20 ml-auto" />
      </button>
    </div>
  );
}

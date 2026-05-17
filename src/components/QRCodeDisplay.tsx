import { QRCodeSVG } from "qrcode.react";
import { save } from "@tauri-apps/plugin-dialog";
import { writeFile } from "@tauri-apps/plugin-fs";
import { cn } from "../utils";
import { toast } from "../toast";

interface QRCodeDisplayProps {
  name: string;
  keyHex: string;
  type: "kem" | "dsa";
  size?: number;
}

/**
 * Convierte una cadena hexadecimal a base64 para reducir el tamaño del payload QR.
 * Hex ocupa 2 chars por byte, base64 ocupa ~1.33 chars por byte → ahorro del 33%.
 * Ejemplo: 3136 hex chars → 2092 base64 chars (cabe en QR Version 40 Level L).
 */
function hexToBase64(hex: string): string {
  const bytes = new Uint8Array(hex.match(/.{1,2}/g)!.map(b => parseInt(b, 16)));
  let binary = "";
  bytes.forEach(b => binary += String.fromCharCode(b));
  return btoa(binary);
}

/**
 * Componente reutilizable que renderiza un QR code con una llave pública PQC.
 * Cada QR contiene un payload JSON compacto con la llave codificada en base64
 * para maximizar la capacidad del QR code.
 */
export function QRCodeDisplay({ name, keyHex, type, size = 200 }: QRCodeDisplayProps) {
  // Generar un ID seguro sin espacios para el DOM
  const safeId = `qr-${type}-${name.replace(/\s+/g, "_")}`;

  // Construir el payload JSON compacto con la llave en base64
  // Formato mínimo: {"a":"CB","v":1,"t":"kem","n":"Nombre","k":"base64..."}
  const payload = {
    a: "CB",       // app identifier
    v: 1,          // version
    t: type,       // "kem" | "dsa"
    n: name,       // nombre del contacto
    k: hexToBase64(keyHex), // llave en base64 (33% más compacto que hex)
  };

  const jsonString = JSON.stringify(payload);

  // Descargar el QR como imagen PNG usando la API nativa de Tauri
  const handleDownload = async () => {
    const svg = document.getElementById(safeId);
    if (!svg) return;

    try {
      const outputPath = await save({
        title: "Guardar QR como imagen",
        defaultPath: `CryptoBro_${name.replace(/\s+/g, "_")}_${type.toUpperCase()}.png`,
        filters: [{ name: "Imagen PNG", extensions: ["png"] }],
      });
      if (!outputPath) return;

      const svgData = new XMLSerializer().serializeToString(svg);
      const canvas = document.createElement("canvas");
      const renderSize = size * 2;
      canvas.width = renderSize;
      canvas.height = renderSize;
      const ctx = canvas.getContext("2d");
      if (!ctx) return;

      const img = new Image();
      await new Promise<void>((resolve, reject) => {
        img.onload = () => resolve();
        img.onerror = () => reject(new Error("Error al renderizar el QR"));
        img.src = "data:image/svg+xml;base64," + btoa(unescape(encodeURIComponent(svgData)));
      });

      ctx.fillStyle = "#ffffff";
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.drawImage(img, 0, 0, canvas.width, canvas.height);

      const dataUrl = canvas.toDataURL("image/png");
      const base64 = dataUrl.split(",")[1];
      const bytes = Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
      await writeFile(outputPath, bytes);
      toast.success("QR guardado como imagen PNG");
    } catch (err) {
      toast.error("Error al guardar el QR: " + String(err));
    }
  };

  return (
    <div className="flex flex-col items-center gap-3">
      {/* Etiqueta del tipo de llave */}
      <span
        className={cn(
          "text-[9px] font-bold uppercase tracking-[0.25em] px-3 py-1 rounded-full border",
          type === "kem"
            ? "text-brand-cyan border-brand-cyan/30 bg-brand-cyan/5"
            : "text-brand-emerald border-brand-emerald/30 bg-brand-emerald/5"
        )}
      >
        {type === "kem" ? "Cifrado (ML-KEM)" : "Verificación (ML-DSA)"}
      </span>

      {/* Contenedor del QR con borde temático */}
      <div
        className={cn(
          "p-3 rounded-2xl border-2 bg-white",
          type === "kem" ? "border-brand-cyan/40" : "border-brand-emerald/40"
        )}
      >
        <QRCodeSVG
          id={safeId}
          value={jsonString}
          size={size}
          level="L"
          bgColor="#ffffff"
          fgColor="#000000"
        />
      </div>

      {/* Botón para descargar el QR como imagen */}
      <button
        onClick={handleDownload}
        className={cn(
          "text-[9px] font-bold uppercase tracking-widest px-4 py-1.5 rounded-xl border transition-all hover:scale-105",
          type === "kem"
            ? "border-brand-cyan/30 text-brand-cyan hover:bg-brand-cyan/10"
            : "border-brand-emerald/30 text-brand-emerald hover:bg-brand-emerald/10"
        )}
      >
        Descargar QR
      </button>
    </div>
  );
}

/**
 * Tipos e interfaces compartidas de CryptoBro.
 * Centralizar aquí evita duplicación y asegura consistencia entre componentes.
 */


export interface Identity {
  kem_pub: string; // Llave pública ML-KEM-1024 (Encapsulación)
  kem_priv: string; // Llave privada ML-KEM-1024 (Decapsulación)
  dsa_pub: string; // Llave pública ML-DSA-65 (Verificación de Firma)
  dsa_priv: string; // Llave privada ML-DSA-65 (Generación de Firma)
}

export interface Contact {
  name: string; // Nombre identificativo del contacto
  public_key: string; // Llave pública PQC (KEM)
  verifier_key: string; // Llave pública de verificación (DSA)
}

export type CryptoMode = 'encrypt' | 'decrypt' | 'stego'; // Modos de operación principal
export type ItemType = 'file' | 'folder'; // Tipo de objeto a procesar
export type CryptoMethod = 'password' | 'quantum'; // Método de cifrado elegido
export type StegoAction = 'hide' | 'extract'; // Acciones dentro del modo esteganografía
export type AuthTarget = 'keys' | null; // Objetivo de la re-autenticación

/**
 * Payload JSON embebido dentro de cada QR code individual.
 * Cada QR contiene UNA sola llave (KEM o DSA) junto con metadatos de identificación.
 * Tamaño máximo: ~3200 chars hex + overhead JSON ≈ cabe en QR Version 40.
 */
export interface QRContactPayload {
  app: "CryptoBro";      // Identificador de la aplicación (evita colisiones con otros QRs)
  v: 1;                   // Versión del formato (para retrocompatibilidad futura)
  type: "kem" | "dsa";   // Tipo de llave contenida
  name: string;           // Nombre del contacto emisor
  key: string;            // Llave pública en formato hexadecimal
}

/**
 * Formato del archivo exportable `.cbrokey`.
 * Contiene AMBAS llaves públicas de un contacto en un solo archivo JSON.
 * Se transfiere por email, USB o chat sin necesidad de cifrado (son llaves públicas).
 */
export interface ContactExportFile {
  app: "CryptoBro";      // Identificador de la aplicación
  v: 1;                   // Versión del formato
  name: string;           // Nombre del contacto
  kem_pub: string;        // Llave pública ML-KEM-1024 (Cifrado)
  dsa_pub: string;        // Llave pública ML-DSA-65 (Verificación)
}

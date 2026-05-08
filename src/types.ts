/**
 * Tipos e interfaces compartidas de CryptoBro.
 * Centralizar aquí evita duplicación y asegura consistencia entre componentes.
 */

export interface ProcessState {
  status: 'idle' | 'processing' | 'success' | 'error'; // Estado actual del flujo de trabajo
  message: string; // Mensaje descriptivo para el usuario
}

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

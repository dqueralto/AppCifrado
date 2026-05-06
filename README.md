# CryptoBro 🛡️ - Advanced Post-Quantum Vault

CryptoBro es una suite de seguridad de grado profesional, diseñada para proteger la información en la era de la computación cuántica. Combina algoritmos de cifrado simétrico tradicionales con los nuevos estándares de criptografía post-cuántica (PQC) de la NIST.

## 🚀 Características Maestras

### 1. Cifrado Híbrido en Cascada (Cascading Encryption)
Cada archivo se asegura bajo dos capas independientes de cifrado simétrico, lo que significa que un atacante tendría que romper dos algoritmos distintos para acceder a los datos:
- **AES-256-GCM:** Estándar de la industria para cifrado de bloques.
- **ChaCha20-Poly1305:** Cifrado de flujo extremadamente seguro y optimizado.

### 2. Identidad Cuántica (ML-KEM & ML-DSA)
CryptoBro implementa los algoritmos finalistas del NIST (FIPS 203 y 204) para garantizar la seguridad del futuro:
- **ML-KEM-1024 (Kyber):** Intercambio de claves resistente a ordenadores cuánticos.
- **ML-DSA-65 (Dilithium):** Firmas digitales infalsificables que garantizan la autenticidad e integridad del remitente.

### 3. Camuflaje de Datos (Esteganografía)
Permite ocultar contenedores cifrados `.vault` dentro de imágenes convencionales (JPG, PNG). El archivo resultante parece una imagen normal, pero contiene tus secretos inyectados de forma invisible mediante la técnica de *EOF-Appending*.

### 4. Borrado Seguro (Safe Shredding)
Implementa un algoritmo de destrucción destructiva basado en el estándar **Gutmann**. Los archivos originales se sobrescriben con patrones aleatorios antes de ser eliminados, impidiendo cualquier intento de recuperación forense.

### 5. Cifrado de Carpetas PQC
Soporta el empaquetado automático de directorios completos mediante contenedores `TAR` con compresión `Gzip` integrada, todo dentro de la misma tubería de cifrado cuántico.

## 🛠️ Arquitectura Técnica

- **Backend:** [Rust](https://www.rust-lang.org/) (Tauri 2.0) - Alto rendimiento y seguridad de memoria.
- **Frontend:** [React](https://reactjs.org/) + [Vite](https://vitejs.dev/) - Interfaz reactiva y fluida.
- **Seguridad:**
  - **Argon2id:** Derivación de claves de alta resistencia contra ataques de fuerza bruta.
  - **Streaming logic:** Procesamiento de archivos grandes (>4GB) sin impacto en la RAM.
- **UI/UX:** Diseño *Glassmorphism* con animaciones de alta fidelidad mediante **Framer Motion**.

## 📦 Instalación y Desarrollo

### Requisitos previos
- [Node.js](https://nodejs.org/) (v18+)
- [Rust](https://www.rust-lang.org/) (Cargo 1.70+)

### Pasos para ejecutar
1. Clonar el repositorio.
2. Instalar dependencias: `npm install`
3. Iniciar entorno de desarrollo: `npm run tauri dev`

## 🔒 Privacidad Local-First

CryptoBro es **completamente offline**. No hay servidores, no hay telemetría, no hay nube. Tus llaves y tus datos nunca salen de tu dispositivo. La seguridad es responsabilidad total del usuario; si pierdes tu identidad cuántica o tu contraseña maestra, los datos son irrecuperables por diseño.

---
**Desarrollado con pasión por la privacidad absoluta.**

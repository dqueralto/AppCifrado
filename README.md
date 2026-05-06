# CryptoBro 🛡️

CryptoBro es una aplicación multiplataforma (Mac, Windows y Linux) diseñada para el cifrado de archivos con seguridad de grado militar y resistencia ante ataques de computación cuántica.

## 🚀 Características Principales

- **Cifrado Híbrido en Cascada:** Cada archivo se asegura bajo dos capas de cifrado simétrico independientes:
  - **AES-256-GCM:** El estándar de oro de la industria.
  - **ChaCha20-Poly1305:** Un cifrado de flujo de alta velocidad y seguridad extrema.
- **Resistencia Cuántica (PQC):** Implementa **ML-KEM-1024** (Kyber), el estándar de la NIST para el intercambio de claves resistente a computadoras cuánticas.
- **Protección contra Fuerza Bruta:** Utiliza **Argon2id** para la derivación de claves a partir de contraseñas, configurado con parámetros de alto coste de memoria para neutralizar ataques mediante GPU o ASICs.
- **Lógica de Streaming:** Capaz de procesar archivos de cualquier tamaño sin saturar la memoria RAM.
- **Interfaz Premium:** Diseño minimalista y moderno con efectos de cristal (glassmorphism) y optimización para macOS.

## 🛠️ Stack Tecnológico

- **Backend:** [Rust](https://www.rust-lang.org/) (Tauri 2.0)
- **Frontend:** [React](https://reactjs.org/) + [Vite](https://vitejs.dev/)
- **Estilos:** [Tailwind CSS v4](https://tailwindcss.com/)
- **Animaciones:** [Framer Motion](https://www.framer.com/motion/)

## 📦 Instalación y Desarrollo

### Requisitos previos
- [Node.js](https://nodejs.org/) (v18+)
- [Rust](https://www.rust-lang.org/) (Cargo 1.70+)

### Pasos para ejecutar
1. Clonar el repositorio.
2. Instalar dependencias de Node:
   ```bash
   npm install
   ```
3. Ejecutar en modo desarrollo:
   ```bash
   npm run tauri dev
   ```

## 🔒 Seguridad

CryptoBro no utiliza servicios en la nube. Todo el procesamiento ocurre de forma local en tu máquina. Las claves se generan y destruyen en memoria, y no existen puertas traseras de recuperación; la pérdida de la clave maestra implica la pérdida irreversible de los datos cifrados.

---
Desarrollado con enfoque en la privacidad total y la seguridad del futuro.

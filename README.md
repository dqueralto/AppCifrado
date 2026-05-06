# 🌌 CryptoBro — Arquitectura Técnica y Guía del Proyecto

Bienvenido a la documentación técnica de **CryptoBro**. Este documento detalla cada decisión arquitectónica, diseño criptográfico, flujo de datos y lógica compleja implementada en la plataforma, diseñada como una suite de seguridad post-cuántica y esteganografía de nivel militar.

---

## 🏗️ 1. Stack Tecnológico y Fundamentos

La aplicación utiliza la arquitectura **Tauri** (Frontend web interactivo + Backend nativo ultrarrápido y seguro) para aprovechar la velocidad y seguridad de Rust en el procesamiento criptográfico, mientras se mantiene una interfaz de usuario moderna.

- **Frontend Core**: [React 18](https://reactjs.org/) + [Vite](https://vitejs.dev/) (para compilación rápida y HMR).
- **Backend & Core Criptográfico**: [Rust](https://www.rust-lang.org/) bajo la plataforma [Tauri v2](https://v2.tauri.app/).
- **Algoritmos Post-Cuánticos**: `ml-kem` (Kyber/FIPS 203) y `dilithium-rs` (ML-DSA/FIPS 204).
- **Algoritmos Simétricos**: `aes-gcm` y `chacha20poly1305`.
- **Derivación de Claves**: `argon2` (Argon2id).
- **Animaciones**: [Framer Motion](https://www.framer.com/motion/) para transiciones de estado, modals modulares y toasts.
- **Iconografía**: [Lucide React](https://lucide.dev/).
- **Estilos**: Tailwind CSS combinado con variables Vanilla CSS para un diseño *Glassmorphism* avanzado.

---

## 📂 2. Estructura de Directorios

```text
/src                      # FRONTEND (React)
 ├── /components          # Componentes UI (no usado extensivamente, lógica en App.tsx)
 ├── App.tsx              # Orquestador principal, lógica de estados y UI centralizada
 ├── index.css            # Design System (Tailwind base y clases de utilidad)
 └── main.tsx             # Punto de entrada de React

/src-tauri/src            # BACKEND (Rust)
 ├── crypto.rs            # Core criptográfico: Cifrado en cascada, PQC y Steganografía
 ├── contacts.rs          # Gestión segura de la libreta de contactos local cifrada
 ├── main.rs              # Punto de entrada de Tauri e inyección de comandos
 └── lib.rs               # Exportación de módulos
```

---

## 📊 3. Modelo de Datos (Contenedores `.vault`)

A diferencia de una base de datos relacional, el "Modelo de Datos" de CryptoBro radica en el diseño a nivel de bits de sus contenedores cifrados (`.vault`). A continuación su estructura técnica:

### Contenedor Estándar (Contraseña)
| Desplazamiento | Longitud | Descripción |
| :--- | :--- | :--- |
| `0x00` | 4 bytes | Magic Bytes (`CBRO`). Verificación estructural instantánea. |
| `0x04` | 1 byte | Flags (Bit 0: Compresión Gzip activada). |
| `0x05` | 16 bytes | Sal aleatoria (Salt) para Argon2id. |
| `0x15` | 12 bytes | Nonce base para AES-256-GCM. |
| `0x21` | 12 bytes | Nonce base para ChaCha20-Poly1305. |
| `0x2D` | Variable | Bloques de datos cifrados (Tamaño + Payload). |

### Contenedor Cuántico (ML-KEM + ML-DSA)
| Desplazamiento | Longitud | Descripción |
| :--- | :--- | :--- |
| `0x00` | 4 bytes | Magic Bytes (`CBRO`). |
| `0x04` | 1 byte | Vault ID (`1` = KEM, `2` = KEM + Firma Digital). |
| `0x05` | 3309 bytes | (Solo si ID = 2) Firma ML-DSA-65. |
| `0xCF2`| 1568 bytes | Ciphertext encapsulado de ML-KEM-1024. |
| `...`  | Variable | Flags, Sal, Nonces y Payload cifrado (igual al Estándar). |

---

## 🔐 4. Seguridad y Arquitectura de Defensas

El sistema ha superado estrictas auditorías técnicas para mitigar ataques conocidos:

1. **Defensa contra Reutilización de Nonce**: AES-GCM es extremadamente vulnerable si se reutiliza un Nonce. La función `derive_block_nonce` utiliza el Nonce base y realiza una operación `XOR` con un contador de 64-bits que incrementa por cada bloque, garantizando unicidad criptográfica.
2. **Cascada Simétrica**: Para proteger contra debilidades futuras en cualquier algoritmo único, los datos se comprimen con Gzip, se cifran primero con AES-256-GCM y luego se envuelven en una capa de ChaCha20-Poly1305.
3. **Seguridad contra Fuerza Bruta**: La libreta de contactos (`contacts.vault`) implementa un limitador local (máximo 5 intentos seguidos) respaldado por un `Mutex<HashMap>` global en Rust, con un bloqueo forzado de 30 segundos. Además, Argon2id utiliza configuración de grado militar (`m=65536, t=3, p=4`).
4. **Protección en Memoria**: La llave privada cuántica jamás se escribe en disco. Permanece en el estado de React solo durante su uso. Un botón "Salir (KEM)" permite al usuario limpiar la memoria de inmediato (Zeroización de contexto frontend). Además, en el backend Rust, las llaves simétricas temporales se sobrescriben con ceros usando el trait `Zeroize` antes de liberar la RAM.
5. **Borrado Seguro (Secure Shredding)**: Implementa el estándar **DoD 5220.22-M** del Departamento de Defensa. Cuando el usuario decide destruir el archivo original, CryptoBro no lo borra simplemente; lo sobrescribe mediante 3 pasadas exhaustivas (Ceros `0x00`, Unos `0xFF` y Ruido criptográfico de `OsRng`) antes de desvincularlo del disco duro. Para carpetas, el borrado es **recursivo**: se aplica `secure_shred` a cada archivo individual antes de eliminar el directorio.
6. **Política de Seguridad de Contenido (CSP)**: El frontend opera bajo un CSP estricto (`default-src 'self'`) que bloquea inyecciones de código remoto (XSS), haciendo imposible la exfiltración de llaves cuánticas a través de internet incluso si el sistema está comprometido.
7. **Anti-Fuga de Datos (Sanitización)**: Los errores del sistema operativo no se propagan a la capa visual para prevenir la filtración de la estructura del árbol de directorios del equipo.

---

## 🖼️ 5. Procesamiento de Archivos y Stego-Streaming

CryptoBro está diseñado para manejar **archivos de varios gigabytes** sin colapsar la RAM del usuario (Prevención de Out of Memory - OOM).

### A. Cifrado / Descifrado en Streaming (`crypto.rs`)
En lugar de `fs::read` completo, se utiliza un bucle con `CHUNK_SIZE = 64KB`. Cada trozo se lee, se comprime, se cifra y se escribe al vuelo en disco.
Para las firmas digitales, se emplea una inserción quirúrgica con `SeekFrom::Start(1)`, sobrescribiendo únicamente los `3309 bytes` correspondientes a la firma sin cargar el contenedor gigante en memoria.

### B. Esteganografía Inteligente
CryptoBro puede ocultar archivos `.vault` dentro de archivos multimedia normales (MKV, PDF, PNG) concatenándolos detrás del marcador `CRYPTOBRO_HIDDEN_DATA_V1`.
Para extraerlos, el sistema no carga la película de 10GB en memoria; en su lugar, utiliza un algoritmo de **ventana deslizante (Sliding Window)** que lee la película en trozos de 64KB, cruzando los límites de los bloques en busca del marcador de 24 bytes de forma eficiente.

---

## 🧩 6. Lógicas Complejas de UI

### Estados de Identidad Cuántica (`App.tsx`)
La gestión de los pares de llaves es compleja porque conviven 4 llaves distintas (Pública/Privada KEM y Pública/Privada DSA).
- **Inyección Transparente:** Al cifrar, si la identidad está cargada en memoria, la UI detecta la llave DSA privada y se la envía al backend para que inyecte la firma de forma automática (creando un contenedor `Vault ID = 2`).
- **Verificación Dinámica:** En la fase de descifrado, si el usuario tiene una firma pegada en el "Verificador (Opcional)" o la selecciona de sus contactos, el backend valida el hash completo del payload contra la llave pública del remitente antes de descifrar.

### Portapapeles Asíncrono
Para copiar llaves públicas extensas, se reemplazó la función bloqueante `alert()` por un estado reactivo (`copiedToast`) gestionado por `Framer Motion`. Esto permite que la aplicación siga operativa mientras se informa al usuario del éxito de la copia.

---

## 🌟 7. Mejoras de Experiencia de Usuario (UX)

Para elevar la calidad del producto y mantener la "ilusión" de inmersión en un entorno ciberpunk/hacker de alta gama:

- **Efecto Glassmorphism**: Componentes flotantes semi-transparentes (`backdrop-blur-3xl`, `bg-black/40`) sobre un fondo oscuro, para una estética premium.
- **Micro-animaciones**: Uso extenso de `framer-motion` para cambios de tamaño de ventanas modales, transiciones entre modos de cifrado (Cifrar vs Descifrar) y toggles (Borrado Seguro).
- **Flujo Guiado de Ayuda**: Integración de una Modal de Guía (`showGuide`) que explica brevemente la diferencia entre los algoritmos simétricos y cuánticos sin salir de la app.
- **Limpieza Automática**: Al completar una acción exitosa, la interfaz resetea automáticamente las contraseñas, llaves en uso y rutas para evitar derrames accidentales de datos (Data Spillage).

---

## 🚀 8. Flujo de Trabajo (Vistas Modulares)

Aunque todo sucede en `App.tsx`, las vistas se renderizan condicionalmente mediante estados booleanos:

1.  **Panel Principal**: Selector central de Método (Contraseña / Cuántico) y Acción (Cifrar, Descifrar, Camuflar). Renderiza los inputs dinámicamente según la combinación elegida.
2.  **Modal de Identidad**: Genera y presenta los nuevos pares de llaves post-cuánticas de manera clara (cajas de solo lectura) para que el usuario las copie y distribuya.
3.  **Libreta de Contactos**: Gestor de pares Nombre-LlavePública. Integrada en el flujo de encriptación para que los usuarios puedan pulsar un contacto y rellenar automáticamente el campo "Llave Pública" del destinatario.
4.  **Flujo Stego**: Interfaz de dos vías; "Ocultar" (pide ruta del archivo original + ruta de la imagen portadora) y "Extraer" (analiza la imagen buscando el marcador).

---

## 🛠️ 9. Mantenimiento y Convenciones

- **Tauri IPC**: Toda la comunicación con Rust ocurre a través de `invoke()`. Los comandos deben devolver la estructura `EncryptResponse` para que el frontend pueda pintar mensajes de error estandarizados sin fallar.
- **Validación de Rutas**: Todo backend debe pasar por la función `validate_path` en Rust para evitar escalada de privilegios o `Directory Traversal` (e.g. `../../etc/passwd`).
- **Lógica Rust**: Siempre que se agreguen nuevos comandos criptográficos, se deben reutilizar las funciones `encrypt_blocks` y `decrypt_blocks` para evitar duplicación del núcleo seguro.
- **Dependencias Ligeras**: No se deben añadir librerías masivas de frontend (como librerías de componentes UI pesadas). Todos los componentes visuales se construyen artesanalmente con `Tailwind` y `Framer Motion` para mantener el bundle pequeño (actualmente compilado en menos de 1MB gzipped).

# 🛡️ CryptoBro: Post-Quantum Security Suite

**CryptoBro** es una suite de seguridad avanzada diseñada para la era de la computación cuántica. Combina la robustez de los algoritmos simétricos tradicionales con los nuevos estándares de criptografía post-cuántica (PQC) de la FIPS (NIST), permitiendo proteger, firmar y camuflar información sensible con un nivel de seguridad sin precedentes.

## 🚀 Características Principales

### 1. ⚛️ Cifrado Híbrido Post-Cuántico
Implementa los estándares más recientes para resistir ataques de ordenadores cuánticos:
*   **ML-KEM-1024 (Kyber):** Establecimiento de llaves con seguridad de nivel 1024 bits.
*   **ML-DSA-65 (Dilithium):** Firmas digitales infalsificables para garantizar la autenticidad e integridad.
*   **Doble Capa Simétrica:** Cascada de cifrado **AES-256-GCM** + **ChaCha20-Poly1305** con derivación de llaves mediante Argon2id.

### 2. 🎭 Esteganografía Universal (Stego-Streaming)
Oculta tus contenedores cifrados dentro de archivos cotidianos para que pasen desapercibidos:
*   **Formatos Soportados:** Imágenes (JPG, PNG), Audio (MP3, WAV), Vídeo (MKV, MP4) y Documentos (PDF).
*   **Tecnología de Streaming:** Capacidad para procesar archivos de **gran tamaño (10GB+)** mediante lectura y escritura por bloques, evitando el consumo excesivo de memoria RAM.
*   **Denegación Plausible:** Un archivo MKV de 10GB que contiene un secreto es indistinguible de una película normal.

### 3. 🔑 Gestión de Identidad Cuántica
*   **Identidad Híbrida:** Generación de un set de 4 llaves (Cifrado Público/Privado + Firma Público/Privado).
*   **Persistencia Segura:** Las llaves se mantienen activas durante la sesión para automatizar la firma de todos los archivos enviados.
*   **Directorio de Contactos:** Agenda integrada para almacenar llaves públicas de verificación de terceros.

### 4. 🧹 Destrucción de Datos (Secure Shredding)
*   **Algoritmo Gutmann:** Eliminación segura de archivos mediante 35 pasadas de sobreescritura aleatoria, haciendo imposible la recuperación de datos incluso con herramientas forenses.

## 🛠️ Especificaciones Técnicas

| Componente | Algoritmo | Estándar |
| :--- | :--- | :--- |
| Cifrado Asimétrico | ML-KEM-1024 | FIPS 203 |
| Firma Digital | ML-DSA-65 | FIPS 204 |
| Cifrado Simétrico 1 | AES-256-GCM | NIST SP 800-38D |
| Cifrado Simétrico 2 | ChaCha20-Poly1305 | RFC 8439 |
| Derivación de Llave | Argon2id | RFC 9106 |
| Compresión | Gzip (Deflate) | RFC 1952 |

## 📖 Guía de Uso Rápido

1.  **Generar Identidad:** Ve al panel inferior y pulsa "Generar Par". Guarda tus llaves en un lugar seguro.
2.  **Cifrar:** Selecciona un archivo o carpeta. Elige "Método Cuántico". Si tu identidad está activa, el archivo se firmará automáticamente.
3.  **Verificar:** Al descifrar, puedes introducir la "Llave de Verificación" del remitente. Si el archivo ha sido manipulado, saltará la **¡ALERTA ROJA!**.
4.  **Camuflar:** Una vez tengas tu archivo `.vault`, ve a la sección "Camuflar", selecciona el contenedor y elige un archivo de vídeo o música como portada.

---

## 🔒 Compromiso de Privacidad
CryptoBro es una aplicación **Local-First**. Ningún dato, llave o archivo sale jamás de tu dispositivo. No hay servidores, no hay telemetría, no hay puertas traseras.

*Desarrollado para aquellos que entienden que la privacidad es un derecho, no un privilegio.*

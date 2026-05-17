# Comparativa Estratégica y Criptográfica: CryptoBro vs. Competidores (Cryptomator, VeraCrypt y AxCrypt)

Este documento presenta un análisis técnico profundo que compara la arquitectura, las primitivas criptográficas y la experiencia de usuario de **CryptoBro (Quantum Vault)** frente a los estándares de la industria actual: **Cryptomator**, **VeraCrypt** y **AxCrypt**.

---

## 1. Matriz de Características Técnicas

| Característica | **CryptoBro (Quantum Vault)** | **Cryptomator** | **VeraCrypt** | **AxCrypt** |
| :--- | :--- | :--- | :--- | :--- |
| **Resistencia Cuántica (PQC)** | **Sí (FIPS 203 ML-KEM-1024 & FIPS 204 ML-DSA-65)** | No (Criptografía Clásica) | No (Criptografía Clásica) | No (Criptografía Clásica) |
| **Algoritmo Simétrico** | **Cascada Híbrida: AES-256-GCM + ChaCha20-Poly1305** | AES-256-GCM | AES-256, Serpent, Twofish (Cascada opcional) | AES-128 / AES-256 |
| **Autenticidad del Remitente** | **Sí (Firma Digital Activa ML-DSA-65)** | No | No | No (Solo clave compartida) |
| **Esteganografía integrada** | **Sí (Ocultamiento en portadores multimedia)** | No | No | No |
| **Arquitectura de Memoria** | **Zero-Footprint (Streaming directo con buffers de 64KB)** | Virtual Drive (FUSE / WebDAV) | Bloques del Sistema de Archivos Virtual | Carga parcial / Archivos temporales |
| **Eficiencia de Sincronización Nube**| Media (Genera un único contenedor `.vault`) | **Alta (Cifrado individual de archivos y nombres)** | Baja (Todo el contenedor cambia) | Alta (Cifrado de archivo individual) |
| **Plausible Deniability** | **Muy Alta (Contenedores camuflados invisibles)** | Nula | Alta (Particiones ocultas) | Nula |

---

## 2. Dónde Gana CryptoBro (Ventajas Competitivas Únicas)

### A. Inmunidad Post-Cuántica (PQC) 
* **El Problema del Competidor:** Cryptomator y VeraCrypt utilizan criptografía de clave pública tradicional (RSA, ECDH) para el intercambio de claves o la configuración de identidad. Si un adversario captura hoy tus archivos cifrados con Cryptomator y los almacena, podrá descifrarlos en el futuro usando un ordenador cuántico mediante el **Algoritmo de Shor** (ataque *Harvest Now, Decrypt Later*).
* **Nuestra Solución:** CryptoBro implementa el estándar definitivo del NIST post-cuántico: **ML-KEM-1024** para la encapsulación de claves y **ML-DSA-65** para la firma de integridad. Somos **inmunes** a la decodificación por computación cuántica.

### B. Cifrado Híbrido en Cascada (AES-256-GCM + ChaCha20-Poly1305)
* Mientras que la mayoría de los competidores implementan únicamente AES-256, CryptoBro cifra los datos en dos capas concurrentes. Si el día de mañana se descubriese una vulnerabilidad de día cero en AES-256, el payload seguiría estando protegido por el flujo de ChaCha20 (y viceversa). Ambas capas utilizan nonces independientes derivados criptográficamente mediante HKDF.

### C. Denegación Plausible Real mediante Esteganografía
* VeraCrypt permite crear volúmenes ocultos (un volumen dentro de otro), pero ante un análisis forense avanzado, la existencia de sectores con alta entropía delata que hay datos ocultos. 
* CryptoBro permite inyectar el archivo `.vault` directamente dentro de imágenes, archivos de audio o vídeo legítimos. Para un observador externo o un cortafuegos de red, estás enviando una foto de tus vacaciones, no una base de datos confidencial.

### D. Firma de Integridad Atómica y Zero-Trust Transfer
* Con Cryptomator, compartes el acceso a una bóveda mediante una clave común, pero no puedes certificar matemáticamente *quién* modificó el archivo.
* En CryptoBro, los archivos cifrados con PQC incorporan una firma **ML-DSA-65** atómica. El receptor puede verificar con certeza matemática que el archivo proviene de tu identidad cuántica y no ha sido alterado ni un solo bit en el camino, previniendo inyecciones maliciosas.

---

## 3. Dónde Gana la Competencia (Áreas de Oportunidad)

### A. Sincronización Incremental en la Nube (El Fuerte de Cryptomator)
* **Cómo funciona Cryptomator:** Está diseñado específicamente para Dropbox, Google Drive, etc. Cifra cada archivo de tu carpeta de forma independiente. Si modificas un archivo de 2KB dentro de una bóveda de 100GB, solo se sincronizan esos 2KB cifrados en la nube.
* **Nuestra Limitación:** CryptoBro empaqueta la carpeta usando `tar` en memoria y la procesa en un único archivo compacto `.vault`. Si modificas una línea de un documento dentro de una carpeta cifrada de 10GB, tendrás que volver a subir todo el archivo `.vault` de 10GB a tu nube. 

### B. Integración Transparente con el Sistema (Virtual Drives)
* **Cómo funciona VeraCrypt/Cryptomator:** Montan una unidad de disco virtual (ej: Unidad `Z:\`). Abres tus programas directamente desde ahí y se descifran en tiempo real al leerlos.
* **Nuestra Limitación:** CryptoBro funciona como un "Archivador Seguro" (modelo similar a 7-Zip pero ultra-cifrado). Debes descifrar el archivo para trabajar en él, y volver a cifrarlo al terminar (aunque el borrado seguro automático mitiga los riesgos de dejar copias huérfanas en claro).

---

## 4. ¿Es CryptoBro "Mejor"? (El Veredicto Estratégico)

> [!IMPORTANT]
> **No es mejor ni peor en términos absolutos: responden a casos de uso radicalmente distintos.**

* **Elige Cryptomator si:** Tu prioridad es la comodidad diaria de trabajar con miles de archivos pequeños que se sincronizan en tiempo real con Google Drive o OneDrive de forma transparente y sin fricción.
* **Elige VeraCrypt si:** Necesitas cifrar todo tu sistema operativo, particiones enteras de disco duro, o crear discos duros externos virtuales de alta capacidad para uso local continuo.
* **Elige CryptoBro (Quantum Vault) si:**
  1. Tu prioridad absoluta es el **espionaje industrial o la protección a nivel de Estado** a largo plazo (inmunidad contra ordenadores cuánticos).
  2. Necesitas compartir archivos y carpetas a través de canales inseguros con la garantía de que **nadie ha suplantado la identidad del emisor** (Firmas ML-DSA).
  3. Requieres **evadir la censura o la vigilancia de red** mediante camuflaje de archivos (Esteganografía).
  4. Buscas un sistema **Zero-Footprint** ultra-ligero que no deje archivos temporales en el disco del ordenador donde se ejecuta.

---

## 5. Próximos Pasos Recomendados para Superar a la Competencia
Para acortar la brecha de usabilidad con Cryptomator sin comprometer nuestra resistencia cuántica, podríamos explorar en el futuro:
1. **Montaje de Unidad Virtual Ligera:** Implementar un sistema de lectura parcial que permita previsualizar el contenido del `.vault` sin extraer la carpeta entera en disco.
2. **Cifrado Multi-Destinatario:** Permitir cifrar una misma bóveda para múltiples llaves públicas ML-KEM de contactos a la vez (al estilo GPG/PGP).

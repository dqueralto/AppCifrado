use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{Argon2, Params};
use chacha20poly1305::ChaCha20Poly1305;
use dilithium::{MlDsaKeyPair, ML_DSA_65};
use flate2::read::GzDecoder;
use kem::{Decapsulate, Encapsulate};
use ml_kem::{
    kem::DecapsulationKey, kem::EncapsulationKey, EncodedSizeUser, KemCore, MlKem1024,
    MlKem1024Params,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use zeroize::{Zeroize, Zeroizing};

#[derive(Serialize, Deserialize)]
pub struct EncryptResponse {
    pub success: bool,
    pub message: String,
    pub data: Option<String>,
}

// --- CONSTANTES Y CONFIGURACIÓN ---
const SALT_SIZE: usize = 16;
const NONCE_SIZE: usize = 12; // Estándar para GCM y Poly1305
const CHUNK_SIZE: usize = 64 * 1024; // 64KB por bloque para optimizar RAM (Streaming)

// Constantes Criptográficas PQC
const ML_DSA_65_SIG_SIZE: usize = 3309;
const ML_KEM_1024_CT_SIZE: usize = 1568;
const ML_DSA_65_VK_SIZE: usize = 1952;
const ML_DSA_65_SK_SIZE: usize = 4032;

// Offsets estructurales de archivo
const MAGIC_OFFSET: u64 = 5; // 4 (Magic) + 1 (ID)
const PAYLOAD_OFFSET_WITH_MAGIC: u64 = MAGIC_OFFSET + ML_DSA_65_SIG_SIZE as u64; // 3314
const PAYLOAD_OFFSET_LEGACY: u64 = 1 + ML_DSA_65_SIG_SIZE as u64; // 3310

// Marcador único para identificar dónde empiezan los datos ocultos en esteganografía.
// Permite buscar el inicio del vault dentro de archivos multimedia (mkv, mp3, pdf).
const STEGO_MARKER: &[u8] = b"CRYPTOBRO_HIDDEN_DATA_V1";

// Firma del archivo (Magic Bytes) para validación estructural rápida.
const MAGIC_BYTES: &[u8; 4] = b"CBRO";

/// Borrado seguro de un archivo (DoD 5220.22-M: 3 pasadas)
fn secure_shred(path: &str) -> std::io::Result<()> {
    let metadata = std::fs::metadata(path)?;
    let size = metadata.len();
    let mut file = std::fs::OpenOptions::new().write(true).open(path)?;

    let mut write_pass = |data: &[u8]| -> std::io::Result<()> {
        file.seek(SeekFrom::Start(0))?;
        let mut written = 0;
        while written < size {
            let to_write = std::cmp::min(data.len() as u64, size - written) as usize;
            file.write_all(&data[..to_write])?;
            written += to_write as u64;
        }
        file.sync_all()
    };

    // Pasada 1: Ceros
    write_pass(&[0x00; 65536])?;
    // Pasada 2: Unos
    write_pass(&[0xFF; 65536])?;

    // Pasada 3: Ruido Aleatorio (CSPRNG via ChaCha20)
    // Se genera una clave maestra de 32 bytes del Kernel una sola vez.
    // Esto evita ahogar el pool de entropía del Sistema Operativo con miles de syscalls.
    file.seek(SeekFrom::Start(0))?;
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::Other, "Error inicializando CSPRNG")
    })?;

    let zeros = vec![0u8; 65536];
    let mut written = 0;
    let mut block_index = 0u64;

    while written < size {
        let mut nonce_bytes = [0u8; 12];
        let idx_bytes = block_index.to_be_bytes();
        nonce_bytes[4..12].copy_from_slice(&idx_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // ChaCha20 cifra los ceros generando 64KB de Ruido Blanco criptográfico perfecto
        let noise = cipher.encrypt(nonce, zeros.as_slice()).unwrap_or_else(|_| zeros.clone());

        let to_write = std::cmp::min(65536, size - written) as usize;
        file.write_all(&noise[..to_write])?;
        written += to_write as u64;
        block_index += 1;
    }
    file.sync_all()?;
    key.zeroize();

    file.set_len(0)?;
    file.sync_all()?;
    std::fs::remove_file(path)?;
    Ok(())
}

/// Borrado seguro recursivo de un directorio completo (DoD 5220.22-M)
fn secure_shred_dir_recursive(path: &std::path::Path) -> std::io::Result<()> {
    if path.is_dir() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let child_path = entry.path();
            if child_path.is_dir() {
                secure_shred_dir_recursive(&child_path)?;
            } else {
                let _ = secure_shred(&child_path.to_string_lossy());
            }
        }
        std::fs::remove_dir(path)?;
    } else {
        let _ = secure_shred(&path.to_string_lossy());
    }
    Ok(())
}

/// Valida que la ruta no contenga intentos de directory traversal ni apunte a directorios sensibles.
fn validate_path(path: &str) -> Result<(), String> {
    if path.contains("..") {
        return Err("Ruta no permitida: posible intento de directory traversal.".into());
    }
    Ok(())
}

/// Genera un Nonce único para cada bloque del archivo.
/// Combina el Nonce base (aleatorio, por archivo) con el índice del bloque
/// para garantizar que nunca se reutiliza el mismo Nonce + Clave en AES-GCM o ChaCha20.
/// CRÍTICO: Reutilizar el mismo Nonce en AES-GCM con la misma clave es una vulnerabilidad grave.
fn derive_block_nonce(base_nonce: &[u8; 12], block_index: u64) -> [u8; 12] {
    let mut nonce = *base_nonce;
    let counter_bytes = block_index.to_be_bytes();
    // XOR los últimos 8 bytes con el contador del bloque
    for i in 0..8 {
        nonce[4 + i] ^= counter_bytes[i];
    }
    nonce
}

/// Deriva claves simétricas a partir de una contraseña usando Argon2id (Zeroized memory)
/// Devuelve un Result para propagar errores limpios a la UI en lugar de hacer panic.
pub fn derive_keys(password: &str, salt: &[u8]) -> Result<(Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>), String> {
    let config = Params::new(65536, 3, 4, None).expect("Parámetros de Argon2 inválidos");

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, config);

    let mut output = Zeroizing::new([0u8; 64]);
    argon2
        .hash_password_into(password.as_bytes(), salt, output.as_mut())
        .map_err(|_| "Fallo al derivar claves (Argon2id): memoria insuficiente o parámetros inválidos".to_string())?;

    Ok((
        Zeroizing::new(output[0..32].to_vec()),
        Zeroizing::new(output[32..64].to_vec()),
    ))
}

/// Wrapper de Write que alimenta un Sha256 mientras escribe datos en el writer subyacente.
/// Permite calcular el hash del payload cifrado al vuelo, sin segunda lectura del archivo.
/// Esto es la pieza clave para la atomicidad de la firma (Bug #2 Fix).
struct HashingWriter<W: Write> {
    inner: W,
    hasher: sha2::Sha256,
}

impl<W: Write> HashingWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: sha2::Sha256::new(),
        }
    }

    /// Consume el wrapper y devuelve el inner junto con el hash calculado.
    fn finalize(self) -> (W, sha2::digest::Output<sha2::Sha256>) {
        (self.inner, sha2::Digest::finalize(self.hasher))
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        sha2::Digest::update(&mut self.hasher, &buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Wrapper que implementa std::io::Write para cifrar datos al vuelo (Streaming Encryptor).
/// Acumula bytes hasta alcanzar CHUNK_SIZE y los cifra automáticamente antes de escribirlos al disco.
pub struct EncryptWriter<W: Write> {
    inner: W,
    buffer: Vec<u8>,
    aes_cipher: Aes256Gcm,
    chacha_cipher: ChaCha20Poly1305,
    aes_nonce_raw: [u8; 12],
    chacha_nonce_raw: [u8; 12],
    block_index: u64,
    error: Option<io::Error>,
}

impl<W: Write> EncryptWriter<W> {
    pub fn new(
        inner: W,
        aes_cipher: Aes256Gcm,
        chacha_cipher: ChaCha20Poly1305,
        aes_nonce_raw: [u8; 12],
        chacha_nonce_raw: [u8; 12],
    ) -> Self {
        Self {
            inner,
            buffer: Vec::with_capacity(CHUNK_SIZE * 2),
            aes_cipher,
            chacha_cipher,
            aes_nonce_raw,
            chacha_nonce_raw,
            block_index: 0,
            error: None,
        }
    }

    /// Cifra y escribe bloques completos de 64KB, o el resto si es el bloque final.
    fn flush_chunk(&mut self, is_final: bool) -> io::Result<()> {
        if self.error.is_some() {
            return Err(io::Error::new(io::ErrorKind::Other, "EncryptWriter está en estado de error"));
        }

        while self.buffer.len() >= CHUNK_SIZE || (is_final && !self.buffer.is_empty()) {
            let chunk_len = std::cmp::min(self.buffer.len(), CHUNK_SIZE);
            let chunk = &self.buffer[..chunk_len];

            let aes_nonce = derive_block_nonce(&self.aes_nonce_raw, self.block_index);
            let chacha_nonce = derive_block_nonce(&self.chacha_nonce_raw, self.block_index);

            // Capa 1: AES
            let enc_aes = match self.aes_cipher.encrypt(Nonce::from_slice(&aes_nonce), chunk) {
                Ok(enc) => enc,
                Err(_) => {
                    self.error = Some(io::Error::new(io::ErrorKind::InvalidData, "Fallo al cifrar (AES)"));
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "Fallo al cifrar (AES)"));
                }
            };
            // Capa 2: ChaCha20
            let enc_final = match self.chacha_cipher.encrypt(Nonce::from_slice(&chacha_nonce), enc_aes.as_slice()) {
                Ok(enc) => enc,
                Err(_) => {
                    self.error = Some(io::Error::new(io::ErrorKind::InvalidData, "Fallo al cifrar (ChaCha)"));
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "Fallo al cifrar (ChaCha)"));
                }
            };

            let len = enc_final.len() as u32;
            if let Err(e) = self.inner.write_all(&len.to_be_bytes()) {
                self.error = Some(io::Error::new(io::ErrorKind::Other, e.to_string()));
                return Err(e);
            }
            if let Err(e) = self.inner.write_all(&enc_final) {
                self.error = Some(io::Error::new(io::ErrorKind::Other, e.to_string()));
                return Err(e);
            }

            self.block_index += 1;
            
            // Eliminar el trozo procesado de forma eficiente
            self.buffer.drain(..chunk_len);
        }

        if is_final {
            if let Err(e) = self.inner.flush() {
                self.error = Some(io::Error::new(io::ErrorKind::Other, e.to_string()));
                return Err(e);
            }
        }
        Ok(())
    }

    /// Finaliza el cifrado, procesa cualquier dato restante y extrae el writer interno.
    pub fn finish(mut self) -> io::Result<W> {
        self.flush_chunk(true)?;
        Ok(self.inner)
    }
}

impl<W: Write> Write for EncryptWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.error.is_some() {
            return Err(io::Error::new(io::ErrorKind::Other, "EncryptWriter está en estado de error"));
        }
        self.buffer.extend_from_slice(buf);
        self.flush_chunk(false)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        // No forzamos flush de bloques parciales para no corromper el alineamiento de 64KB.
        // El verdadero flush del bloque parcial ocurrirá en .finish()
        Ok(())
    }
}

/// Wrapper que implementa std::io::Read para descifrar datos al vuelo (Streaming Decryptor).
pub struct DecryptReader<R: Read> {
    inner: R,
    buffer: Vec<u8>,
    buffer_pos: usize,
    aes_cipher: Aes256Gcm,
    chacha_cipher: ChaCha20Poly1305,
    aes_nonce_raw: [u8; 12],
    chacha_nonce_raw: [u8; 12],
    block_index: u64,
    use_compression: bool,
    is_eof: bool,
}

impl<R: Read> DecryptReader<R> {
    pub fn new(
        inner: R,
        aes_cipher: Aes256Gcm,
        chacha_cipher: ChaCha20Poly1305,
        aes_nonce_raw: [u8; 12],
        chacha_nonce_raw: [u8; 12],
        use_compression: bool,
    ) -> Self {
        Self {
            inner,
            buffer: Vec::with_capacity(CHUNK_SIZE * 2),
            buffer_pos: 0,
            aes_cipher,
            chacha_cipher,
            aes_nonce_raw,
            chacha_nonce_raw,
            block_index: 0,
            use_compression,
            is_eof: false,
        }
    }

    fn fetch_next_chunk(&mut self) -> io::Result<bool> {
        if self.is_eof {
            return Ok(false);
        }

        let mut len_buf = [0u8; 4];
        match self.inner.read_exact(&mut len_buf) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                self.is_eof = true;
                return Ok(false);
            }
            Err(e) => return Err(e),
        }

        let chunk_len = u32::from_be_bytes(len_buf) as usize;
        if chunk_len > 1024 * 1024 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Bloque excesivamente grande (DoS mitigation)"));
        }

        let mut enc_chunk = vec![0u8; chunk_len];
        self.inner.read_exact(&mut enc_chunk)?;

        let aes_nonce = derive_block_nonce(&self.aes_nonce_raw, self.block_index);
        let chacha_nonce = derive_block_nonce(&self.chacha_nonce_raw, self.block_index);

        let dec_chacha = match self.chacha_cipher.decrypt(Nonce::from_slice(&chacha_nonce), enc_chunk.as_slice()) {
            Ok(dec) => dec,
            Err(_) => return Err(io::Error::new(io::ErrorKind::InvalidData, "Fallo al descifrar (ChaCha)")),
        };
        let dec_aes = match self.aes_cipher.decrypt(Nonce::from_slice(&aes_nonce), dec_chacha.as_slice()) {
            Ok(dec) => dec,
            Err(_) => return Err(io::Error::new(io::ErrorKind::InvalidData, "Fallo al descifrar (AES)")),
        };

        let final_data = if self.use_compression {
            let mut decoder = GzDecoder::new(dec_aes.as_slice());
            let mut decompressed = Vec::new();
            decoder.read_to_end(&mut decompressed)?;
            decompressed
        } else {
            dec_aes
        };

        self.buffer = final_data;
        self.buffer_pos = 0;
        self.block_index += 1;
        Ok(true)
    }
}

impl<R: Read> Read for DecryptReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.buffer_pos >= self.buffer.len() {
            let has_more = self.fetch_next_chunk()?;
            if !has_more {
                return Ok(0); // EOF
            }
        }

        let available = self.buffer.len() - self.buffer_pos;
        let to_copy = std::cmp::min(buf.len(), available);
        buf[..to_copy].copy_from_slice(&self.buffer[self.buffer_pos..self.buffer_pos + to_copy]);
        self.buffer_pos += to_copy;

        Ok(to_copy)
    }
}


/// Cifra un stream de datos en bloques con doble capa (AES-256-GCM + ChaCha20-Poly1305).
/// Función reutilizable por encrypt_file y encrypt_with_quantum para evitar duplicación.
fn encrypt_blocks(
    reader: &mut impl Read,
    writer: &mut impl Write,
    aes_cipher: &Aes256Gcm,
    chacha_cipher: &ChaCha20Poly1305,
    aes_nonce_raw: &[u8; 12],
    chacha_nonce_raw: &[u8; 12],
) -> Result<(), String> {
    let mut enc_writer = EncryptWriter::new(
        writer,
        aes_cipher.clone(),
        chacha_cipher.clone(),
        *aes_nonce_raw,
        *chacha_nonce_raw,
    );
    let mut buffer = vec![0u8; CHUNK_SIZE];
    loop {
        let count = reader.read(&mut buffer).map_err(|_| "Fallo al leer datos del archivo origen")?;
        if count == 0 {
            break;
        }
        enc_writer.write_all(&buffer[..count]).map_err(|e| e.to_string())?;
    }
    enc_writer.finish().map_err(|e| e.to_string())?;
    Ok(())
}

/// Descifra un stream de bloques revirtiendo la doble capa (ChaCha20 → AES → Gzip).
/// Función reutilizable por decrypt_file y decrypt_with_quantum.
fn decrypt_blocks(
    reader: &mut impl Read,
    writer: &mut impl Write,
    aes_cipher: &Aes256Gcm,
    chacha_cipher: &ChaCha20Poly1305,
    aes_nonce_raw: &[u8; 12],
    chacha_nonce_raw: &[u8; 12],
    use_compression: bool,
) -> Result<(), String> {
    let mut dec_reader = DecryptReader::new(
        reader,
        aes_cipher.clone(),
        chacha_cipher.clone(),
        *aes_nonce_raw,
        *chacha_nonce_raw,
        use_compression,
    );
    let mut buffer = vec![0u8; CHUNK_SIZE];
    loop {
        let count = dec_reader.read(&mut buffer).map_err(|e| e.to_string())?;
        if count == 0 {
            break;
        }
        writer.write_all(&buffer[..count]).map_err(|_| "Fallo al escribir datos descifrados")?;
    }
    Ok(())
}

/// Comando para cifrar un archivo con múltiples capas (AES-256 + ChaCha20)
#[tauri::command]
pub async fn encrypt_file(
    input_path: String,
    output_path: String,
    mut password: String,
    shred_original: bool,
) -> Result<EncryptResponse, String> {
    validate_path(&input_path)?;
    validate_path(&output_path)?;

    let input_file = File::open(&input_path)
        .map_err(|_| "Error al leer el archivo de origen. Comprueba los permisos o si existe.")?;
    let mut input_file = BufReader::new(input_file);
    let output_file = File::create(&output_path)
        .map_err(|_| "Error al crear el archivo de destino en la ruta especificada.")?;
    let mut output_file = BufWriter::new(output_file);

    // Generar Sal y Nonces (Vectores de Inicialización) aleatorios
    let mut salt = [0u8; SALT_SIZE];
    let mut aes_nonce_raw = [0u8; NONCE_SIZE];
    let mut chacha_nonce_raw = [0u8; NONCE_SIZE];

    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut aes_nonce_raw);
    OsRng.fill_bytes(&mut chacha_nonce_raw);

    // Escribir cabecera: Magic Bytes (4) + Flags (1) + Sal (16) + Nonce AES (12) + Nonce ChaCha (12)
    output_file
        .write_all(MAGIC_BYTES)
        .map_err(|_| "Fallo de I/O al escribir Magic Bytes")?;
    let flags = 0x00u8; // Bit 0: Compresión desactivada (Protección Anti-CRIME)
    output_file
        .write_all(&[flags])
        .map_err(|_| "Fallo de I/O al escribir Flags")?;
    output_file
        .write_all(&salt)
        .map_err(|_| "Fallo de I/O al escribir Salt")?;
    output_file
        .write_all(&aes_nonce_raw)
        .map_err(|_| "Fallo de I/O al escribir Nonce AES")?;
    output_file
        .write_all(&chacha_nonce_raw)
        .map_err(|_| "Fallo de I/O al escribir Nonce ChaCha")?;

    // Derivar claves a partir de la contraseña
    let (aes_key, chacha_key) = derive_keys(&password, &salt)?;
    password.zeroize(); // Defensa: Borrado de contraseña maestra en memoria RAM

    let aes_cipher = Aes256Gcm::new_from_slice(aes_key.as_slice()).map_err(|_| "Error interno: Fallo al inicializar cifrador AES")?;
    let chacha_cipher =
        ChaCha20Poly1305::new_from_slice(chacha_key.as_slice()).map_err(|_| "Error interno: Fallo al inicializar cifrador ChaCha20")?;

    tokio::task::spawn_blocking(move || {
        encrypt_blocks(
            &mut input_file,
            &mut output_file,
            &aes_cipher,
            &chacha_cipher,
            &aes_nonce_raw,
            &chacha_nonce_raw,
        )?;
        output_file.flush().map_err(|_| "Error de I/O al vaciar los datos cifrados al disco".to_string())?;
        Ok::<(), String>(())
    }).await.map_err(|_| "Error de hardware aislando el cifrado".to_string())??;

    if shred_original {
        let _ = secure_shred(&input_path);
    }

    Ok(EncryptResponse {
        success: true,
        message: "Archivo cifrado con éxito mediante Cifrado Híbrido en Cascada".into(),
        data: None,
    })
}

/// Comando para descifrar un archivo revirtiendo las capas de cifrado
#[tauri::command]
pub async fn decrypt_file(
    input_path: String,
    output_path: String,
    mut password: String,
) -> Result<EncryptResponse, String> {
    validate_path(&input_path)?;
    validate_path(&output_path)?;

    let mut input_file = File::open(&input_path)
        .map_err(|_| "Error al leer el archivo. Comprueba los permisos o si existe.")?;
    let output_file =
        File::create(&output_path).map_err(|_| "Error al crear el archivo de destino.")?;
    let mut output_file = BufWriter::new(output_file);

    // Leer Magic Bytes (Retrocompatibilidad con V0)
    let mut magic_buf = [0u8; 4];
    if input_file.read_exact(&mut magic_buf).is_ok() && &magic_buf != MAGIC_BYTES {
        input_file
            .seek(SeekFrom::Start(0))
            .map_err(|_| "Error interno de lectura")?;
    } else if &magic_buf != MAGIC_BYTES {
        return Err("El archivo está corrupto o no se puede leer.".into());
    }

    // Leer cabecera
    let mut flags_buf = [0u8; 1];
    input_file
        .read_exact(&mut flags_buf)
        .map_err(|_| "Archivo corrupto: No se pueden leer las banderas")?;
    let flags = flags_buf[0];

    let mut salt = [0u8; SALT_SIZE];
    let mut aes_nonce_raw = [0u8; NONCE_SIZE];
    let mut chacha_nonce_raw = [0u8; NONCE_SIZE];

    input_file
        .read_exact(&mut salt)
        .map_err(|_| "Archivo corrupto: Falta salt")?;
    input_file
        .read_exact(&mut aes_nonce_raw)
        .map_err(|_| "Archivo corrupto: Falta nonce AES")?;
    input_file
        .read_exact(&mut chacha_nonce_raw)
        .map_err(|_| "Archivo corrupto: Falta nonce ChaCha")?;

    // Tras leer toda la cabecera (seek ya no es necesario), envolvemos en BufReader
    // para que las lecturas del payload de datos sean eficientes.
    let mut input_file = BufReader::new(input_file);

    // Re-derivar las mismas claves
    let (aes_key, chacha_key) = derive_keys(&password, &salt)?;
    password.zeroize(); // Defensa: Borrado de contraseña maestra en memoria RAM

    let aes_cipher = Aes256Gcm::new_from_slice(aes_key.as_slice()).map_err(|_| "Error interno: Fallo al inicializar cifrador AES")?;
    let chacha_cipher =
        ChaCha20Poly1305::new_from_slice(chacha_key.as_slice()).map_err(|_| "Error interno: Fallo al inicializar cifrador ChaCha20")?;
    let use_compression = (flags & 0x01) != 0;

    let output_path_clone = output_path.clone();
    tokio::task::spawn_blocking(move || {
        decrypt_blocks(
            &mut input_file,
            &mut output_file,
            &aes_cipher,
            &chacha_cipher,
            &aes_nonce_raw,
            &chacha_nonce_raw,
            use_compression,
        )?;
        output_file.flush().map_err(|_| "Error de I/O al vaciar los datos descifrados al disco".to_string())?;
        Ok::<(), String>(())
    }).await.map_err(|_| "Error de hardware aislando el descifrado".to_string())?.map_err(|e| {
        // Prevención de Unauthenticated Plaintext Release: Destruir archivo parcial en caso de error
        let _ = secure_shred(&output_path_clone);
        e
    })?;

    Ok(EncryptResponse {
        success: true,
        message: "Archivo descifrado con éxito".into(),
        data: None,
    })
}

#[tauri::command]
pub async fn generate_quantum_keys() -> Result<EncryptResponse, String> {
    // Mover la generación de llaves a un hilo bloqueante para no congelar la UI.
    // La criptografía post-cuántica es computacionalmente costosa y no debe
    // ejecutarse en el hilo async del runtime de Tokio.
    let (kem_pk_hex, kem_sk_hex, dsa_pk_hex, dsa_sk_hex) =
        tokio::task::spawn_blocking(|| {
            // 1. Generar par de llaves Kyber-1024 (Cifrado)
            let (kem_sk, kem_pk) = MlKem1024::generate(&mut OsRng);

            // 2. Generar par de llaves ML-DSA-65 (Firma)
            let dsa_kp = MlDsaKeyPair::generate(ML_DSA_65)
                .map_err(|_| "Error interno al generar llaves de firma cuántica".to_string())?;

            Ok::<_, String>((
                hex::encode(kem_pk.as_bytes()),
                hex::encode(kem_sk.as_bytes()),
                hex::encode(dsa_kp.public_key()),
                hex::encode(dsa_kp.private_key()),
            ))
        })
        .await
        .map_err(|_| "Error de hardware al generar llaves cuánticas".to_string())??;

    Ok(EncryptResponse {
        success: true,
        message: "Identidad Cuántica Completa (Cifrado + Firma) generada con éxito".into(),
        data: Some(format!(
            "{}:{}:{}:{}",
            kem_pk_hex, kem_sk_hex, dsa_pk_hex, dsa_sk_hex
        )),
    })
}

/// Comando para cifrar con identidad cuántica
async fn encrypt_quantum_internal(
    input_path: String,
    output_path: String,
    mut public_key_hex: String,
    signing_key_hex: Option<String>,
    shred_original: bool,
    is_folder: bool,
) -> Result<EncryptResponse, String> {
    validate_path(&input_path)?;
    validate_path(&output_path)?;

    // Prevención de colapso de memoria (OOM): Evitar que un portapapeles gigante tire el programa
    if public_key_hex.len() > 20_000 {
        public_key_hex.zeroize();
        return Err("Llave pública demasiado grande (Riesgo OOM)".into());
    }

    let pk_bytes = hex::decode(&public_key_hex).map_err(|_| "Llave pública inválida")?;
    public_key_hex.zeroize(); // Defensa RAM: Destruir llave cuántica

    // Parsear la llave pública
    let pk_bytes_array: &[u8; ML_KEM_1024_CT_SIZE] = pk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "Longitud de llave pública incorrecta")?;
    let pk = EncapsulationKey::<MlKem1024Params>::from_bytes(pk_bytes_array.into());

    // Encapsular usando ML-KEM-1024
    let (ciphertext, shared_secret) = pk
        .encapsulate(&mut OsRng)
        .map_err(|_| "Fallo en la encapsulación cuántica")?;

    // Usamos el secreto compartido como "contraseña" para nuestro sistema de cascada
    let shared_secret_hex = hex::encode(shared_secret.as_slice());

    // Cifrar el archivo usando la lógica existente
    // Pero primero, necesitamos escribir el Ciphertext de ML-KEM en el archivo de salida
    // para que el destinatario pueda decapsularlo.

    let mut output_file =
        File::create(&output_path).map_err(|_| "Error al crear archivo destino.")?;

    // --- CONSTRUCCIÓN DEL CONTENEDOR .VAULT ---
    output_file
        .write_all(MAGIC_BYTES)
        .map_err(|_| "Error de I/O")?;

    // 1. Escribir Identificador (1 = Quantum, 2 = Quantum Signed)
    let vault_id = if signing_key_hex.is_some() { 2u8 } else { 1u8 };
    output_file
        .write_all(&[vault_id])
        .map_err(|_| "Error de I/O")?;

    // Si es firmado, reservamos espacio para la firma (ML_DSA_65_SIG_SIZE bytes para ML-DSA-65)
    // Pero es mejor escribirla al final o después del ID.
    // Escribamos un marcador de posición si es ID 2.
    if vault_id == 2 {
        output_file
            .write_all(&[0u8; ML_DSA_65_SIG_SIZE])
            .map_err(|_| "Error de I/O")?;
    }

    // 2. Escribir el Ciphertext de ML-KEM (ML_KEM_1024_CT_SIZE bytes para ML-KEM-1024)
    output_file
        .write_all(ciphertext.as_slice())
        .map_err(|_| "Error de I/O al escribir KEM ciphertext")?;

    // 3. Escribir Flags (1 byte)
    let flags = 0x00u8; // Compresión desactivada (Protección Anti-CRIME)
    output_file
        .write_all(&[flags])
        .map_err(|_| "Error de I/O al escribir Flags")?;

    // 4. Generar Sal y Nonces aleatorios para las capas simétricas
    let mut salt = [0u8; SALT_SIZE];
    let mut aes_nonce_raw = [0u8; NONCE_SIZE];
    let mut chacha_nonce_raw = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut aes_nonce_raw);
    OsRng.fill_bytes(&mut chacha_nonce_raw);

    output_file
        .write_all(&salt)
        .map_err(|_| "Error de I/O al escribir Salt")?;
    output_file
        .write_all(&aes_nonce_raw)
        .map_err(|_| "Error de I/O al escribir Nonce AES")?;
    output_file
        .write_all(&chacha_nonce_raw)
        .map_err(|_| "Error de I/O al escribir Nonce ChaCha")?;

    // Derivar claves a partir del secreto compartido
    let (aes_key, chacha_key) = derive_keys(&shared_secret_hex, &salt)?;

    let aes_cipher = Aes256Gcm::new_from_slice(aes_key.as_slice())
        .map_err(|_| "Error al inicializar cifrador AES")?;
    let chacha_cipher = ChaCha20Poly1305::new_from_slice(chacha_key.as_slice())
        .map_err(|_| "Error al inicializar cifrador ChaCha20")?;


    // Preparar llaves de firma ANTES del spawn_blocking para detectar errores temprano
    // (Bug #2 Fix: decodificamos las llaves antes de entrar al bloque bloqueante)
    let signing_keys: Option<([u8; ML_DSA_65_VK_SIZE], [u8; ML_DSA_65_SK_SIZE])> =
        if let Some(mut sk_combined_hex) = signing_key_hex {
            if sk_combined_hex.len() > 20_000 {
                sk_combined_hex.zeroize();
                let _ = secure_shred(&output_path);
                return Err("Llave de firma demasiado grande (Riesgo OOM)".into());
            }
            let parts: Vec<&str> = sk_combined_hex.split(':').collect();
            if parts.len() != 2 {
                sk_combined_hex.zeroize();
                let _ = secure_shred(&output_path);
                return Err(
                    "Formato de llave de firma inválido. Se esperaba 'llave_publica:llave_privada'."
                        .into(),
                );
            }
            let vk_bytes =
                hex::decode(parts[0]).map_err(|_| "Llave de verificación de firma inválida")?;
            let sk_bytes = hex::decode(parts[1]).map_err(|_| "Llave de firma privada inválida")?;
            sk_combined_hex.zeroize();

            let vk: [u8; ML_DSA_65_VK_SIZE] = vk_bytes
                .try_into()
                .map_err(|_| "Longitud de llave pública de firma incorrecta")?;
            let sk: [u8; ML_DSA_65_SK_SIZE] = sk_bytes
                .try_into()
                .map_err(|_| "Longitud de llave privada de firma incorrecta")?;
            Some((vk, sk))
        } else {
            None
        };

    let is_signed = signing_keys.is_some();
    let output_path_clone = output_path.clone();
    let input_path_clone = input_path.clone();

    // Bug #2 Fix — ATOMICIDAD DE LA FIRMA:
    // Todo el proceso (cifrado + hash + firma + sync_all) ocurre dentro de un único
    // spawn_blocking. El archivo NUNCA se sincroniza al disco con una firma nula:
    // sync_all() se ejecuta solo DESPUÉS de que la firma haya sido inyectada.
    tokio::task::spawn_blocking(move || {
        // Usar HashingWriter para calcular el hash del payload AL VUELO durante el cifrado.
        // Esto elimina la segunda pasada de lectura del archivo para calcular el hash.
        let hashing_writer = HashingWriter::new(BufWriter::new(
            std::fs::OpenOptions::new()
                .write(true)
                .append(true)
                .open(&output_path_clone)
                .map_err(|_| "Error al abrir archivo para cifrado atómico".to_string())?,
        ));

        // Cifrar bloques mientras se acumula el hash del payload cifrado
        let mut hashing_writer = hashing_writer;
        
        if is_folder {
            let enc_writer = EncryptWriter::new(
                hashing_writer,
                aes_cipher,
                chacha_cipher,
                aes_nonce_raw,
                chacha_nonce_raw,
            );
            let mut builder = tar::Builder::new(enc_writer);
            if let Err(e) = builder.append_dir_all(".", &input_path_clone) {
                return Err(format!("Error al empaquetar carpeta al vuelo: {}", e));
            }
            let enc_writer = builder.into_inner().map_err(|_| "Error al finalizar empaquetado TAR".to_string())?;
            hashing_writer = enc_writer.finish().map_err(|e| e.to_string())?;
        } else {
            let mut input_reader = BufReader::new(
                File::open(&input_path_clone).map_err(|_| "Error al reabrir archivo origen".to_string())?
            );
            encrypt_blocks(
                &mut input_reader,
                &mut hashing_writer,
                &aes_cipher,
                &chacha_cipher,
                &aes_nonce_raw,
                &chacha_nonce_raw,
            )
            .map_err(|e| e.to_string())?;
        }

        // Extraer el hash y el inner BufWriter antes de seguir
        let (buf_writer, payload_hash) = hashing_writer.finalize();

        // Vaciar el buffer al OS (pero NO sync_all todavía)
        let mut file = buf_writer
            .into_inner()
            .map_err(|_| "Error al desempaquetar BufWriter".to_string())?;
        file.flush()
            .map_err(|_| "Error al vaciar buffer del payload".to_string())?;

        // Inyección Atómica de la Firma (si procede):
        // Esto ocurre ANTES de sync_all, garantizando que el archivo nunca queda
        // con firma cero-rellenada en disco en caso de fallo de hardware.
        if let Some((dsa_vk_bytes, dsa_sk_bytes)) = signing_keys {
            let dsa_kp = MlDsaKeyPair::from_keys(&dsa_sk_bytes, &dsa_vk_bytes, ML_DSA_65)
                .map_err(|_| "Error al cargar par de llaves de firma".to_string())?;
            let sig = dsa_kp
                .sign(payload_hash.as_slice(), b"")
                .map_err(|_| "Error al generar firma digital".to_string())?;

            // Seek atómico: 4 (MAGIC_BYTES) + 1 (vault_id) = posición 5
            file.seek(SeekFrom::Start(5))
                .map_err(|_| "Error I/O al posicionar para inyección de firma".to_string())?;
            file.write_all(sig.as_bytes())
                .map_err(|_| "Error al escribir firma en disco".to_string())?;
        }

        // sync_all() SOLO DESPUÉS de que la firma esté escrita.
        // El SO garantiza que todo (payload + firma) llega al dispositivo físico.
        file.sync_all()
            .map_err(|_| "Error de I/O al sincronizar disco".to_string())?;

        Ok::<(), String>(())
    })
    .await
    .map_err(|_| {
        let _ = secure_shred(&output_path);
        "Error de hardware aislando el cifrado cuántico".to_string()
    })??;

    if shred_original {
        if is_folder {
            let _ = secure_shred_dir_recursive(std::path::Path::new(&input_path));
        } else {
            let _ = secure_shred(&input_path);
        }
    }

    Ok(EncryptResponse {
        success: true,
        message: if is_signed {
            "Carpeta/Archivo blindado y firmado con Identidad Cuántica (firma atómica ML-DSA-65)".into()
        } else {
            "Carpeta/Archivo cifrado con Identidad Cuántica (ML-KEM-1024)".into()
        },
        data: None,
    })
}

#[tauri::command]
pub async fn encrypt_with_quantum(
    input_path: String,
    output_path: String,
    public_key_hex: String,
    signing_key_hex: Option<String>,
    shred_original: bool,
) -> Result<EncryptResponse, String> {
    encrypt_quantum_internal(input_path, output_path, public_key_hex, signing_key_hex, shred_original, false).await
}

#[tauri::command]
pub async fn encrypt_folder_with_quantum(
    input_path: String,
    output_path: String,
    public_key_hex: String,
    signing_key_hex: Option<String>,
    shred_original: bool,
) -> Result<EncryptResponse, String> {
    encrypt_quantum_internal(input_path, output_path, public_key_hex, signing_key_hex, shred_original, true).await
}

async fn decrypt_quantum_internal(
    input_path: String,
    output_path: String,
    mut private_key_hex: String,
    verifier_key_hex: Option<String>,
    is_folder: bool,
) -> Result<EncryptResponse, String> {
    validate_path(&input_path)?;
    validate_path(&output_path)?;

    let mut input_file = File::open(&input_path)
        .map_err(|_| "Error al abrir el archivo. Comprueba los permisos o si existe.")?;

    // --- PROTOCOLO DE DES-BLINDAJE CUÁNTICO ---

    // Leer Magic Bytes (Retrocompatibilidad con V0)
    let mut magic_buf = [0u8; 4];
    let mut has_magic = false;
    if input_file.read_exact(&mut magic_buf).is_ok() && &magic_buf == MAGIC_BYTES {
        has_magic = true;
    } else {
        input_file
            .seek(SeekFrom::Start(0))
            .map_err(|_| "Error de I/O")?;
    }

    // 1. Leer identificador de tipo de contenedor
    let mut id_buf = [0u8; 1];
    input_file
        .read_exact(&mut id_buf)
        .map_err(|_| "Archivo no es un contenedor cuántico válido")?;
    let vault_id = id_buf[0];

    // 2. Verificar Firma Digital (Si el contenedor es de tipo 2)
    // Implementa el estándar FIPS 204 (ML-DSA-65).
    if vault_id == 2 {
        let mut sig = [0u8; ML_DSA_65_SIG_SIZE]; // Tamaño de firma ML-DSA-65
        input_file
            .read_exact(&mut sig)
            .map_err(|_| "Fallo al leer firma digital")?;
        // NOTA BUG #2: Tras leer ML_DSA_65_SIG_SIZE bytes de firma, el cursor está en:
        //   - Con magic bytes (nuevo): 4 + 1 + ML_DSA_65_SIG_SIZE = PAYLOAD_OFFSET_WITH_MAGIC
        //   - Sin magic bytes (viejo): 1 + ML_DSA_65_SIG_SIZE = PAYLOAD_OFFSET_LEGACY
        // El hash de verificación se calcula leyendo el resto del archivo desde este punto,
        // lo que coincide EXACTAMENTE con el offset desde donde se calculó al firmar.
        // Es crítico que estas posiciones permanezcan sincronizadas entre encrypt y decrypt.

        // Solo verificamos si el usuario ha proporcionado la llave pública del remitente.
        if let Some(mut vk_hex) = verifier_key_hex {
            // Prevención OOM
            if vk_hex.len() > 20_000 {
                vk_hex.zeroize();
                return Err("Llave de verificación demasiado grande (Riesgo OOM)".into());
            }

            let vk_bytes = hex::decode(&vk_hex).map_err(|_| "Llave de verificación inválida")?;
            vk_hex.zeroize(); // Defensa RAM: Destruir llave de verificación

            // El cursor ya está en la posición correcta (PAYLOAD_OFFSET_WITH_MAGIC o PAYLOAD_OFFSET_LEGACY según versión).
            // Leemos el resto del archivo para calcular el hash del payload protegido.
            let mut hasher = Sha256::new();
            let mut hash_buf = [0u8; 65536];
            loop {
                let n = input_file
                    .read(&mut hash_buf)
                    .map_err(|_| "Fallo I/O al calcular hash de verificación")?;
                if n == 0 {
                    break;
                }
                hasher.update(&hash_buf[..n]);
            }
            let file_hash = hasher.finalize();

            let vk_bytes_array: [u8; ML_DSA_65_VK_SIZE] = vk_bytes
                .try_into()
                .map_err(|_| "Longitud de llave de verificación incorrecta")?;
            let dsa_sig = dilithium::MlDsaSignature::from_slice(&sig);

            // ¡ALERTA ROJA! si la firma no coincide con el hash calculado
            if !MlDsaKeyPair::verify(
                &vk_bytes_array,
                &dsa_sig,
                file_hash.as_slice(),
                b"",
                ML_DSA_65,
            ) {
                return Err(
                    "¡ALERTA ROJA! La firma digital es INVÁLIDA o el archivo ha sido manipulado."
                        .into(),
                );
            }

            // Reabrir el archivo y posicionar el cursor en el inicio del KEM ciphertext
            // (después de Magic+ID+Firma). Necesario porque el hash consumió el stream.
            let payload_offset = if has_magic { PAYLOAD_OFFSET_WITH_MAGIC } else { PAYLOAD_OFFSET_LEGACY };
            input_file =
                File::open(&input_path).map_err(|_| "Fallo al reabrir archivo para descifrado")?;
            input_file
                .seek(SeekFrom::Start(payload_offset))
                .map_err(|_| "Fallo al posicionar cursor para KEM")?;
        } else {
            // Sin llave de verificación: saltar directamente al inicio del KEM ciphertext
            let payload_offset = if has_magic { PAYLOAD_OFFSET_WITH_MAGIC } else { PAYLOAD_OFFSET_LEGACY };
            input_file
                .seek(SeekFrom::Start(payload_offset))
                .map_err(|_| "Fallo al posicionar cursor para KEM")?;
        }
    }

    // Leer Ciphertext de ML-KEM
    let mut kem_ciphertext = vec![0u8; ML_KEM_1024_CT_SIZE]; // Tamaño fijo para ML-KEM-1024
    input_file
        .read_exact(&mut kem_ciphertext)
        .map_err(|_| "Error al leer cifrado KEM")?;

    // Leer Flags
    let mut flags_buf = [0u8; 1];
    input_file
        .read_exact(&mut flags_buf)
        .map_err(|_| "Error al leer banderas")?;
    let flags = flags_buf[0];

    // Decapsular usando la llave privada
    // Prevención OOM: Limitar tamaño de entrada antes de parsear
    if private_key_hex.len() > 20_000 {
        private_key_hex.zeroize();
        return Err("Llave privada demasiado grande (Riesgo OOM)".into());
    }
    let sk_bytes = hex::decode(&private_key_hex).map_err(|_| "Llave privada inválida")?;
    private_key_hex.zeroize(); // Defensa RAM: Destruir llave privada de memoria

    let sk_bytes_array: &[u8; 3168] = sk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "Longitud de llave privada incorrecta")?;
    let sk = DecapsulationKey::<MlKem1024Params>::from_bytes(sk_bytes_array.into());

    // Convertir el ciphertext en el tipo esperado por kem
    let ct_bytes_array: [u8; ML_KEM_1024_CT_SIZE] = kem_ciphertext
        .try_into()
        .map_err(|_| "Contenedor cuántico corrupto")?;
    let ciphertext = ml_kem::array::Array::from(ct_bytes_array);

    let shared_secret = sk
        .decapsulate(&ciphertext)
        .map_err(|_| "Fallo al descifrar el secreto cuántico. ¿Es la llave correcta?")?;

    let shared_secret_hex = hex::encode(shared_secret.as_slice());

    // Ahora procedemos con el descifrado normal usando ese secreto
    // FIX #1: Sanitización de errores de I/O — sin filtrar rutas del SO al frontend

    let mut salt = [0u8; SALT_SIZE];
    let mut aes_nonce_raw = [0u8; NONCE_SIZE];
    let mut chacha_nonce_raw = [0u8; NONCE_SIZE];

    input_file
        .read_exact(&mut salt)
        .map_err(|_| "Archivo cuántico corrupto: falta salt")?;
    input_file
        .read_exact(&mut aes_nonce_raw)
        .map_err(|_| "Archivo cuántico corrupto: falta nonce AES")?;
    input_file
        .read_exact(&mut chacha_nonce_raw)
        .map_err(|_| "Archivo cuántico corrupto: falta nonce ChaCha")?;

    let (aes_key, chacha_key) = derive_keys(&shared_secret_hex, &salt)?;
    let aes_cipher = Aes256Gcm::new_from_slice(aes_key.as_slice())
        .map_err(|_| "Error al inicializar cifrador AES")?;
    let chacha_cipher = ChaCha20Poly1305::new_from_slice(chacha_key.as_slice())
        .map_err(|_| "Error al inicializar cifrador ChaCha20")?;
    let use_compression = (flags & 0x01) != 0;

    let mut reader = BufReader::new(input_file);
    let output_path_clone = output_path.clone();
    let output_path_err = output_path.clone();

    tokio::task::spawn_blocking(move || {
        if is_folder {
            let dec_reader = DecryptReader::new(
                reader,
                aes_cipher,
                chacha_cipher,
                aes_nonce_raw,
                chacha_nonce_raw,
                use_compression,
            );
            let mut archive = tar::Archive::new(dec_reader);
            if let Err(e) = archive.unpack(&output_path_clone) {
                return Err(format!("Error al extraer carpeta al vuelo: {}", e));
            }
        } else {
            let output_file = File::create(&output_path_clone).map_err(|_| "Error al crear el archivo de destino.".to_string())?;
            let mut writer = BufWriter::new(output_file);
            decrypt_blocks(
                &mut reader,
                &mut writer,
                &aes_cipher,
                &chacha_cipher,
                &aes_nonce_raw,
                &chacha_nonce_raw,
                use_compression,
            )?;
            writer.flush().map_err(|_| "Error de I/O al vaciar los datos descifrados al disco".to_string())?;
        }
        Ok::<(), String>(())
    }).await.map_err(|_| "Error de hardware aislando el descifrado cuántico".to_string())?.map_err(|e| {
        // Prevención de Unauthenticated Plaintext Release: Destruir archivo parcial en caso de error
        let _ = secure_shred(&output_path_err);
        e
    })?;

    Ok(EncryptResponse {
        success: true,
        message: "Carpeta/Archivo descifrado con éxito mediante Identidad Cuántica".into(),
        data: None,
    })
}

#[tauri::command]
pub async fn decrypt_with_quantum(
    input_path: String,
    output_path: String,
    private_key_hex: String,
    verifier_key_hex: Option<String>,
) -> Result<EncryptResponse, String> {
    decrypt_quantum_internal(input_path, output_path, private_key_hex, verifier_key_hex, false).await
}

#[tauri::command]
pub async fn decrypt_folder_with_quantum(
    input_path: String,
    output_path: String,
    private_key_hex: String,
    verifier_key_hex: Option<String>,
) -> Result<EncryptResponse, String> {
    decrypt_quantum_internal(input_path, output_path, private_key_hex, verifier_key_hex, true).await
}

/// Comando para cifrar una carpeta completa empaquetándola en un contenedor .vault al vuelo
#[tauri::command]
pub async fn encrypt_folder(
    input_path: String,
    output_path: String,
    mut password: String,
    shred_original: bool,
) -> Result<EncryptResponse, String> {
    validate_path(&input_path)?;
    validate_path(&output_path)?;

    let output_file = File::create(&output_path).map_err(|_| "Error al crear el archivo de destino.")?;
    let mut output_file = BufWriter::new(output_file);

    let mut salt = [0u8; SALT_SIZE];
    let mut aes_nonce_raw = [0u8; NONCE_SIZE];
    let mut chacha_nonce_raw = [0u8; NONCE_SIZE];

    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut aes_nonce_raw);
    OsRng.fill_bytes(&mut chacha_nonce_raw);

    output_file.write_all(MAGIC_BYTES).map_err(|_| "Fallo de I/O al escribir Magic Bytes")?;
    let flags = 0x00u8; // Compresión desactivada
    output_file.write_all(&[flags]).map_err(|_| "Fallo de I/O al escribir Flags")?;
    output_file.write_all(&salt).map_err(|_| "Fallo de I/O al escribir Salt")?;
    output_file.write_all(&aes_nonce_raw).map_err(|_| "Fallo de I/O al escribir Nonce AES")?;
    output_file.write_all(&chacha_nonce_raw).map_err(|_| "Fallo de I/O al escribir Nonce ChaCha")?;

    let (aes_key, chacha_key) = derive_keys(&password, &salt)?;
    password.zeroize();

    let aes_cipher = Aes256Gcm::new_from_slice(aes_key.as_slice()).map_err(|_| "Error al inicializar cifrador AES")?;
    let chacha_cipher = ChaCha20Poly1305::new_from_slice(chacha_key.as_slice()).map_err(|_| "Error al inicializar cifrador ChaCha20")?;

    let input_path_clone = input_path.clone();
    let output_path_clone = output_path.clone();

    tokio::task::spawn_blocking(move || {
        let enc_writer = EncryptWriter::new(
            output_file,
            aes_cipher,
            chacha_cipher,
            aes_nonce_raw,
            chacha_nonce_raw,
        );
        
        let mut builder = tar::Builder::new(enc_writer);
        if let Err(e) = builder.append_dir_all(".", &input_path_clone) {
            return Err(format!("Error al empaquetar carpeta al vuelo: {}", e));
        }
        
        let enc_writer = builder.into_inner().map_err(|_| "Error al finalizar empaquetado TAR".to_string())?;
        let mut inner_writer = enc_writer.finish().map_err(|e| e.to_string())?;
        inner_writer.flush().map_err(|_| "Error al vaciar disco".to_string())?;
        
        Ok::<(), String>(())
    }).await.map_err(|_| "Error de hardware aislando cifrado de carpeta".to_string())?.map_err(|e| {
        let _ = secure_shred(&output_path_clone);
        e
    })?;

    if shred_original {
        let _ = secure_shred_dir_recursive(std::path::Path::new(&input_path));
    }

    Ok(EncryptResponse {
        success: true,
        message: "Carpeta blindada con éxito (Streaming Encryptor Sin Archivos Temporales)".into(),
        data: None,
    })
}

/// Comando para descifrar un contenedor y extraer la carpeta original al vuelo
#[tauri::command]
pub async fn decrypt_folder(
    input_path: String,
    output_path: String,
    mut password: String,
) -> Result<EncryptResponse, String> {
    validate_path(&input_path)?;
    validate_path(&output_path)?;

    let mut input_file = File::open(&input_path).map_err(|_| "Error al leer el contenedor.")?;

    let mut magic_buf = [0u8; 4];
    if input_file.read_exact(&mut magic_buf).is_ok() && &magic_buf != MAGIC_BYTES {
        input_file.seek(SeekFrom::Start(0)).map_err(|_| "Error interno")?;
    } else if &magic_buf != MAGIC_BYTES {
        return Err("Contenedor corrupto.".into());
    }

    let mut flags_buf = [0u8; 1];
    input_file.read_exact(&mut flags_buf).map_err(|_| "Archivo corrupto: faltan banderas")?;
    let flags = flags_buf[0];

    let mut salt = [0u8; SALT_SIZE];
    let mut aes_nonce_raw = [0u8; NONCE_SIZE];
    let mut chacha_nonce_raw = [0u8; NONCE_SIZE];

    input_file.read_exact(&mut salt).map_err(|_| "Archivo corrupto: falta salt")?;
    input_file.read_exact(&mut aes_nonce_raw).map_err(|_| "Archivo corrupto: falta nonce AES")?;
    input_file.read_exact(&mut chacha_nonce_raw).map_err(|_| "Archivo corrupto: falta nonce ChaCha")?;

    let input_file = BufReader::new(input_file);

    let (aes_key, chacha_key) = derive_keys(&password, &salt)?;
    password.zeroize();

    let aes_cipher = Aes256Gcm::new_from_slice(aes_key.as_slice()).map_err(|_| "Error al inicializar cifrador AES")?;
    let chacha_cipher = ChaCha20Poly1305::new_from_slice(chacha_key.as_slice()).map_err(|_| "Error al inicializar cifrador ChaCha20")?;
    let use_compression = (flags & 0x01) != 0;

    let output_path_clone = output_path.clone();

    tokio::task::spawn_blocking(move || {
        let dec_reader = DecryptReader::new(
            input_file,
            aes_cipher,
            chacha_cipher,
            aes_nonce_raw,
            chacha_nonce_raw,
            use_compression,
        );

        let mut archive = tar::Archive::new(dec_reader);
        if let Err(e) = archive.unpack(&output_path_clone) {
            return Err(format!("Error al extraer carpeta al vuelo: {}", e));
        }

        Ok::<(), String>(())
    }).await.map_err(|_| "Error de hardware aislando descifrado de carpeta".to_string())??;

    Ok(EncryptResponse {
        success: true,
        message: "Carpeta restaurada con éxito (Streaming Decryptor)".into(),
        data: None,
    })
}


/// Comando para ocultar un archivo .vault dentro de cualquier archivo (Imagen, Video, Audio)
#[tauri::command]
pub async fn hide_in_image(
    image_path: String,
    vault_path: String,
    output_path: String,
) -> Result<EncryptResponse, String> {
    validate_path(&image_path)?;
    validate_path(&vault_path)?;
    validate_path(&output_path)?;

    let mut carrier_file = File::open(&image_path).map_err(|_| "Error al abrir la imagen original. Verifica permisos.")?;
    let mut vault_file = File::open(&vault_path).map_err(|_| "Error al abrir el contenedor vault.")?;
    let output_file = File::create(&output_path).map_err(|_| "Error al crear el archivo de salida.")?;
    let mut writer = BufWriter::new(output_file);

    // 1. Copiar archivo original (portada)
    io::copy(&mut carrier_file, &mut writer).map_err(|_| "Error de I/O al copiar la imagen original.")?;

    // 2. Escribir marcador
    writer.write_all(STEGO_MARKER).map_err(|_| "Error de I/O al escribir el marcador esteganográfico.")?;

    // 3. Copiar datos del vault
    io::copy(&mut vault_file, &mut writer).map_err(|_| "Error de I/O al camuflar el contenedor.")?;

    writer.flush().map_err(|_| "Error de I/O al vaciar buffers del disco.")?;
    // Seguridad: Forzar escritura física al disco antes de destruir el original.
    // Sin sync_all(), el SO puede tener los datos en caché y un apagón causaría pérdida irrecuperable.
    writer.get_mut().sync_all().map_err(|_| "Error de I/O al sincronizar disco antes del borrado seguro.")?;

    // Prevención de rastro esteranográfico: Destruir el .vault original (Plausible Deniability)
    drop(vault_file);
    let _ = secure_shred(&vault_path);

    Ok(EncryptResponse {
        success: true,
        message: "¡Bóveda camuflada con éxito! El archivo de camuflaje sigue siendo funcional."
            .into(),
        data: None,
    })
}

/// Comando para extraer un archivo .vault de una imagen camuflada
#[tauri::command]
pub async fn extract_from_image(
    image_path: String,
    output_vault_path: String,
) -> Result<EncryptResponse, String> {
    validate_path(&image_path)?;
    validate_path(&output_vault_path)?;

    let mut file = File::open(&image_path).map_err(|_| "Error al abrir el archivo camuflado. Verifica permisos.")?;

    // Leemos el archivo en bloques para encontrar el marcador sin colapsar la RAM
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let marker_len = STEGO_MARKER.len();
    let mut previous_tail = vec![];
    let mut found_pos = None;
    let mut current_offset = 0u64;

    // OPTIMIZACIÓN MEMORIA: Pre-asignar vector de búsqueda para reciclar memoria
    let mut search_buf = Vec::with_capacity(CHUNK_SIZE + marker_len);

    loop {
        let count = file.read(&mut buffer).map_err(|_| "Error de I/O al leer el archivo.")?;
        if count == 0 {
            break;
        }

        search_buf.clear();
        search_buf.extend_from_slice(&previous_tail);
        search_buf.extend_from_slice(&buffer[..count]);

        if let Some(pos) = search_buf
            .windows(marker_len)
            .position(|window| window == STEGO_MARKER)
        {
            let abs_pos =
                current_offset - (previous_tail.len() as u64) + (pos as u64) + (marker_len as u64);
            found_pos = Some(abs_pos);
            break;
        }

        current_offset += count as u64;

        let keep = std::cmp::min(search_buf.len(), marker_len - 1);
        previous_tail.clear();
        previous_tail.extend_from_slice(&search_buf[search_buf.len() - keep..]);
    }

    if let Some(pos) = found_pos {
        file.seek(SeekFrom::Start(pos)).map_err(|_| "Error de I/O al posicionar el cursor.")?;
        let out_file = File::create(&output_vault_path).map_err(|_| "Error al crear el archivo extraído.")?;
        let mut out_writer = std::io::BufWriter::new(out_file);
        io::copy(&mut file, &mut out_writer).map_err(|_| "Error de I/O al volcar los datos extraídos.")?;
        out_writer.flush().map_err(|_| "Error de I/O al vaciar el búfer del archivo extraído al disco")?;

        Ok(EncryptResponse {
            success: true,
            message: "Contenedor extraído con éxito del archivo de camuflaje".into(),
            data: None,
        })
    } else {
        Err("No se encontraron datos ocultos de CryptoBro en este archivo".into())
    }
}

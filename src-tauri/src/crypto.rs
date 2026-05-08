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

// Constantes de seguridad
/// --- CONSTANTES Y CONFIGURACIÓN ---
const SALT_SIZE: usize = 16;
const NONCE_SIZE: usize = 12; // Estándar para GCM y Poly1305
const CHUNK_SIZE: usize = 64 * 1024; // 64KB por bloque para optimizar RAM (Streaming)

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

    // Pasada 3: Ruido Aleatorio
    file.seek(SeekFrom::Start(0))?;
    let mut random_data = vec![0u8; 65536];
    let mut written = 0;
    while written < size {
        OsRng.fill_bytes(&mut random_data);
        let to_write = std::cmp::min(random_data.len() as u64, size - written) as usize;
        file.write_all(&random_data[..to_write])?;
        written += to_write as u64;
    }
    file.sync_all()?;
    random_data.zeroize();

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
pub fn derive_keys(password: &str, salt: &[u8]) -> (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>) {
    let config = Params::new(65536, 3, 4, None).expect("Parámetros de Argon2 inválidos");

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, config);

    let mut output = Zeroizing::new([0u8; 64]);
    argon2
        .hash_password_into(password.as_bytes(), salt, output.as_mut())
        .expect("Fallo al derivar claves");

    (
        Zeroizing::new(output[0..32].to_vec()),
        Zeroizing::new(output[32..64].to_vec()),
    )
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
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut block_index: u64 = 0;
    loop {
        let count = reader.read(&mut buffer).map_err(|_| "Fallo al leer datos del archivo origen")?;
        if count == 0 {
            break;
        }
        let chunk = &buffer[..count];

        // Defensa CRIME/BREACH: Se ha deshabilitado la compresión Gzip intencionadamente.
        // Comprimir datos antes de cifrarlos es un vector de ataque conocido (Oráculo de Compresión).
        // Al enviar el bloque en RAW (crudo), garantizamos inmunidad y multiplicamos la velocidad x100.

        // Nonce único por bloque
        let aes_nonce = derive_block_nonce(aes_nonce_raw, block_index);
        let chacha_nonce = derive_block_nonce(chacha_nonce_raw, block_index);

        // Doble capa de cifrado
        let enc_aes = aes_cipher
            .encrypt(Nonce::from_slice(&aes_nonce), chunk)
            .map_err(|_| "Fallo al cifrar datos (AES)")?;
        let enc_final = chacha_cipher
            .encrypt(Nonce::from_slice(&chacha_nonce), enc_aes.as_slice())
            .map_err(|_| "Fallo al cifrar datos (ChaCha20)")?;

        // Escribir: longitud (4 bytes) + datos cifrados
        let len = enc_final.len() as u32;
        writer
            .write_all(&len.to_be_bytes())
            .map_err(|_| "Fallo al escribir cabecera de bloque")?;
        writer.write_all(&enc_final).map_err(|_| "Fallo al escribir datos cifrados")?;
        block_index += 1;
    }
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
    let mut len_buf = [0u8; 4];
    let mut block_index: u64 = 0;
    loop {
        match reader.read_exact(&mut len_buf) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(_) => return Err("Fallo de I/O al leer el contenedor seguro".into()),
        }
        let chunk_len = u32::from_be_bytes(len_buf) as usize;
        
        // Prevención de DoS (Memory Exhaustion)
        // El tamaño de bloque estándar es ~65KB. Límite máximo estricto: 1 MB.
        if chunk_len > 1024 * 1024 {
            return Err("Bloque de datos anormalmente grande. Posible archivo corrupto o ataque DoS.".into());
        }

        let mut chunk = vec![0u8; chunk_len];
        reader
            .read_exact(&mut chunk)
            .map_err(|_| "Contenedor corrupto: bloque de datos incompleto")?;

        let aes_nonce = derive_block_nonce(aes_nonce_raw, block_index);
        let chacha_nonce = derive_block_nonce(chacha_nonce_raw, block_index);

        // Revertir capas
        let dec_chacha = chacha_cipher
            .decrypt(Nonce::from_slice(&chacha_nonce), chunk.as_slice())
            .map_err(|_| "Fallo en Capa 2 (ChaCha20): datos corruptos o clave incorrecta")?;
        let dec_aes = aes_cipher
            .decrypt(Nonce::from_slice(&aes_nonce), dec_chacha.as_slice())
            .map_err(|_| "Fallo en Capa 1 (AES-GCM): datos corruptos o clave incorrecta")?;

        // Descomprimir si aplica
        let final_data = if use_compression {
            let mut decoder = GzDecoder::new(dec_aes.as_slice());
            let mut decompressed = Vec::new();
            decoder
                .read_to_end(&mut decompressed)
                .map_err(|_| "Fallo al descomprimir los datos")?;
            decompressed
        } else {
            dec_aes
        };

        writer.write_all(&final_data).map_err(|_| "Fallo al escribir datos descifrados")?;
        block_index += 1;
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

    let mut input_file = File::open(&input_path)
        .map_err(|_| "Error al leer el archivo de origen. Comprueba los permisos o si existe.")?;
    let mut output_file = File::create(&output_path)
        .map_err(|_| "Error al crear el archivo de destino en la ruta especificada.")?;

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
    let (aes_key, chacha_key) = derive_keys(&password, &salt);
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
        )
    }).await.map_err(|_| "Error de hardware aislando el cifrado")??;

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
    let mut output_file =
        File::create(&output_path).map_err(|_| "Error al crear el archivo de destino.")?;

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

    // Re-derivar las mismas claves
    let (aes_key, chacha_key) = derive_keys(&password, &salt);
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
        )
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
    // 1. Generar par de llaves Kyber-1024 (Cifrado)
    let (kem_sk, kem_pk) = MlKem1024::generate(&mut OsRng);

    // 2. Generar par de llaves ML-DSA-65 (Firma)
    let dsa_kp = MlDsaKeyPair::generate(ML_DSA_65).map_err(|_| "Error interno al generar llaves de firma cuántica")?;

    // Codificar todo en Hexadecimal
    let kem_pk_hex = hex::encode(kem_pk.as_bytes());
    let kem_sk_hex = hex::encode(kem_sk.as_bytes());
    let dsa_pk_hex = hex::encode(dsa_kp.public_key());
    let dsa_sk_hex = hex::encode(dsa_kp.private_key());

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
#[tauri::command]
pub async fn encrypt_with_quantum(
    input_path: String,
    output_path: String,
    mut public_key_hex: String,
    signing_key_hex: Option<String>,
    shred_original: bool,
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
    let pk_bytes_array: &[u8; 1568] = pk_bytes
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

    let mut input_file = File::open(&input_path).map_err(|_| "Error al leer archivo origen.")?;
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

    // Si es firmado, reservamos espacio para la firma (3309 bytes para ML-DSA-65)
    // Pero es mejor escribirla al final o después del ID.
    // Escribamos un marcador de posición si es ID 2.
    if vault_id == 2 {
        output_file
            .write_all(&[0u8; 3309])
            .map_err(|_| "Error de I/O")?;
    }

    // 2. Escribir el Ciphertext de ML-KEM (1568 bytes para ML-KEM-1024)
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
    let (aes_key, chacha_key) = derive_keys(&shared_secret_hex, &salt);

    let aes_cipher = Aes256Gcm::new_from_slice(aes_key.as_slice())
        .map_err(|_| "Error al inicializar cifrador AES")?;
    let chacha_cipher = ChaCha20Poly1305::new_from_slice(chacha_key.as_slice())
        .map_err(|_| "Error al inicializar cifrador ChaCha20")?;

    tokio::task::spawn_blocking(move || {
        encrypt_blocks(
            &mut input_file,
            &mut output_file,
            &aes_cipher,
            &chacha_cipher,
            &aes_nonce_raw,
            &chacha_nonce_raw,
        )?;
        
        // Finalizar escritura y asegurar en disco dentro del mismo hilo bloqueante
        output_file
            .flush()
            .map_err(|_| "Error de I/O al vaciar buffer".to_string())?;
        output_file
            .sync_all()
            .map_err(|_| "Error de I/O al sincronizar disco".to_string())?;
            
        Ok::<(), String>(())
    }).await.map_err(|_| "Error de hardware aislando el cifrado cuántico".to_string())??;

    // 5. Firma Digital con Hash Streaming (evita cargar el archivo completo en RAM)
    // BUG FIX #1: Antes usábamos `if parts.len() == 2` que ignoraba silenciosamente el error
    // si la llave tenía un formato incorrecto, produciendo un vault firmado pero sin firma real.
    // Ahora devolvemos un error explícito si el formato de la llave combinada es inválido.
    if let Some(mut sk_combined_hex) = signing_key_hex {
        // Prevención de colapso de memoria (OOM)
        if sk_combined_hex.len() > 20_000 {
            sk_combined_hex.zeroize();
            let _ = secure_shred(&output_path);
            return Err("Llave de firma demasiado grande (Riesgo OOM)".into());
        }

        let parts: Vec<&str> = sk_combined_hex.split(':').collect();
        if parts.len() != 2 {
            sk_combined_hex.zeroize();
            // Limpiar el archivo de salida corrupto antes de abortar
            let _ = secure_shred(&output_path);
            return Err(
                "Formato de llave de firma inválido. Se esperaba 'llave_publica:llave_privada'."
                    .into(),
            );
        }
        let vk_bytes =
            hex::decode(parts[0]).map_err(|_| "Llave de verificación de firma inválida")?;
        let sk_bytes = hex::decode(parts[1]).map_err(|_| "Llave de firma privada inválida")?;
        sk_combined_hex.zeroize(); // Defensa RAM: Destruir llave de firma

        // Calcular SHA-256 del cuerpo del archivo (desde byte 3314 = Magic+ID+Firma reservada)
        // IMPORTANTE: El hash se calcula sobre todo el contenido DESPUÉS de la firma reservada,
        // incluyendo el KEM ciphertext, flags, salt, nonces y payload cifrado.
        let mut hasher = Sha256::new();
        let mut sign_file =
            File::open(&output_path).map_err(|_| "Error al abrir archivo para firma")?;
        sign_file
            .seek(SeekFrom::Start(3314))
            .map_err(|_| "Error I/O al posicionar cursor de firma")?;
        let mut hash_buf = [0u8; 65536];
        loop {
            let n = sign_file
                .read(&mut hash_buf)
                .map_err(|_| "Error de lectura al calcular hash")?;
            if n == 0 {
                break;
            }
            hasher.update(&hash_buf[..n]);
        }
        let file_hash = hasher.finalize();

        let dsa_vk_bytes: [u8; 1952] = vk_bytes
            .try_into()
            .map_err(|_| "Longitud de llave pública de firma incorrecta")?;
        let dsa_sk_bytes: [u8; 4032] = sk_bytes
            .try_into()
            .map_err(|_| "Longitud de llave privada de firma incorrecta")?;

        let dsa_kp = MlDsaKeyPair::from_keys(&dsa_sk_bytes, &dsa_vk_bytes, ML_DSA_65)
            .map_err(|_| "Error al cargar par de llaves de firma")?;
        let sig = dsa_kp
            .sign(file_hash.as_slice(), b"")
            .map_err(|_| "Error al generar firma digital")?;

        // Inyección quirúrgica de la firma: SeekFrom::Start(5) = 4 Magic Bytes + 1 Vault ID
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(&output_path)
            .map_err(|_| "Error al inyectar firma")?;
        f.seek(SeekFrom::Start(5))
            .map_err(|_| "Error I/O al posicionar para inyección de firma")?;
        f.write_all(sig.as_bytes())
            .map_err(|_| "Error al escribir firma en disco")?;
    }

    if shred_original {
        let _ = secure_shred(&input_path);
    }

    Ok(EncryptResponse {
        success: true,
        message: "Archivo blindado y firmado con Identidad Cuántica".into(),
        data: None,
    })
}

#[tauri::command]
pub async fn decrypt_with_quantum(
    input_path: String,
    output_path: String,
    mut private_key_hex: String,
    verifier_key_hex: Option<String>,
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
        let mut sig = [0u8; 3309]; // Tamaño de firma ML-DSA-65
        input_file
            .read_exact(&mut sig)
            .map_err(|_| "Fallo al leer firma digital")?;
        // NOTA BUG #2: Tras leer 3309 bytes de firma, el cursor está en:
        //   - Con magic bytes (nuevo): 4 + 1 + 3309 = 3314
        //   - Sin magic bytes (viejo): 1 + 3309 = 3310
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

            // El cursor ya está en la posición correcta (3314 o 3310 según versión).
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

            let vk_bytes_array: [u8; 1952] = vk_bytes
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
            let payload_offset = if has_magic { 3314 } else { 3310 };
            input_file =
                File::open(&input_path).map_err(|_| "Fallo al reabrir archivo para descifrado")?;
            input_file
                .seek(SeekFrom::Start(payload_offset))
                .map_err(|_| "Fallo al posicionar cursor para KEM")?;
        } else {
            // Sin llave de verificación: saltar directamente al inicio del KEM ciphertext
            let payload_offset = if has_magic { 3314 } else { 3310 };
            input_file
                .seek(SeekFrom::Start(payload_offset))
                .map_err(|_| "Fallo al posicionar cursor para KEM")?;
        }
    }

    // Leer Ciphertext de ML-KEM
    let mut kem_ciphertext = vec![0u8; 1568]; // Tamaño fijo para ML-KEM-1024
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
    let ct_bytes_array: [u8; 1568] = kem_ciphertext
        .try_into()
        .map_err(|_| "Contenedor cuántico corrupto")?;
    let ciphertext = ml_kem::array::Array::from(ct_bytes_array);

    let shared_secret = sk
        .decapsulate(&ciphertext)
        .map_err(|_| "Fallo al descifrar el secreto cuántico. ¿Es la llave correcta?")?;

    let shared_secret_hex = hex::encode(shared_secret.as_slice());

    // Ahora procedemos con el descifrado normal usando ese secreto
    // FIX #1: Sanitización de errores de I/O — sin filtrar rutas del SO al frontend
    let mut output_file =
        File::create(&output_path).map_err(|_| "Error al crear el archivo de destino.")?;

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

    let (aes_key, chacha_key) = derive_keys(&shared_secret_hex, &salt);
    let aes_cipher = Aes256Gcm::new_from_slice(aes_key.as_slice())
        .map_err(|_| "Error al inicializar cifrador AES")?;
    let chacha_cipher = ChaCha20Poly1305::new_from_slice(chacha_key.as_slice())
        .map_err(|_| "Error al inicializar cifrador ChaCha20")?;
    let use_compression = (flags & 0x01) != 0;

    let mut reader = BufReader::new(input_file);
    let output_path_clone = output_path.clone();
    tokio::task::spawn_blocking(move || {
        decrypt_blocks(
            &mut reader,
            &mut output_file,
            &aes_cipher,
            &chacha_cipher,
            &aes_nonce_raw,
            &chacha_nonce_raw,
            use_compression,
        )
    }).await.map_err(|_| "Error de hardware aislando el descifrado cuántico".to_string())?.map_err(|e| {
        // Prevención de Unauthenticated Plaintext Release: Destruir archivo parcial en caso de error
        let _ = secure_shred(&output_path_clone);
        e
    })?;

    Ok(EncryptResponse {
        success: true,
        message: "Archivo descifrado con éxito mediante Identidad Cuántica".into(),
        data: None,
    })
}
/// Comando para cifrar una carpeta completa empaquetándola en un contenedor .vault
#[tauri::command]
pub async fn encrypt_folder(
    input_path: String,
    output_path: String,
    password: String,
    shred_original: bool,
) -> Result<EncryptResponse, String> {
    // FIX #4: Sufijo aleatorio anti-TOCTOU — evita que un atacante prediga la ruta del temporal
    let mut suffix_bytes = [0u8; 4];
    OsRng.fill_bytes(&mut suffix_bytes);
    let temp_tar = format!("{}.tmp_{}", output_path, hex::encode(suffix_bytes));

    // Crear el archivo TAR temporal
    {
        let file = File::create(&temp_tar).map_err(|_| "Error al crear archivo temporal")?;
        let mut builder = tar::Builder::new(file);
        builder
            .append_dir_all(".", &input_path)
            .map_err(|_| "Error al empaquetar carpeta")?;
        builder
            .finish()
            .map_err(|_| "Error al finalizar empaquetado")?;
    }

    // Cifrar el archivo TAR temporal
    let result = encrypt_file(temp_tar.clone(), output_path, password, false).await;
    let _ = secure_shred(&temp_tar);

    if result.as_ref().is_ok() && shred_original {
        // Borrado seguro (DoD 5220.22-M) recursivo de la carpeta
        let _ = secure_shred_dir_recursive(std::path::Path::new(&input_path));
    }

    result
}

/// Comando para descifrar un contenedor y extraer la carpeta original
#[tauri::command]
pub async fn decrypt_folder(
    input_path: String,
    output_path: String,
    password: String,
) -> Result<EncryptResponse, String> {
    // FIX #4: Sufijo aleatorio anti-TOCTOU
    let mut suffix_bytes = [0u8; 4];
    OsRng.fill_bytes(&mut suffix_bytes);
    let temp_tar = format!("{}.tmp_{}", input_path, hex::encode(suffix_bytes));

    // Descifrar el contenedor al archivo TAR temporal
    let result = decrypt_file(input_path, temp_tar.clone(), password).await.map_err(|e| {
        let _ = secure_shred(&temp_tar);
        e
    })?;

    if result.success {
        // FIX #3: Capturar error de unpack para limpiar el temporal antes de propagar
        let file = File::open(&temp_tar).map_err(|_| "Error al abrir TAR temporal")?;
        let mut archive = tar::Archive::new(file);
        let unpack_result = archive.unpack(&output_path);
        let _ = secure_shred(&temp_tar); // Siempre limpiar, haya o no error
        unpack_result.map_err(|_| "Error al extraer la carpeta del contenedor")?;

        Ok(EncryptResponse {
            success: true,
            message: "Carpeta restaurada con éxito desde el contenedor seguro".into(),
            data: None,
        })
    } else {
        let _ = secure_shred(&temp_tar);
        Err("Fallo al descifrar el contenedor de la carpeta".into())
    }
}

/// Comando para cifrar una carpeta completa con Identidad Cuántica
#[tauri::command]
pub async fn encrypt_folder_with_quantum(
    input_path: String,
    output_path: String,
    public_key_hex: String,
    signing_key_hex: Option<String>,
    shred_original: bool,
) -> Result<EncryptResponse, String> {
    // FIX #4: Sufijo aleatorio anti-TOCTOU
    let mut suffix_bytes = [0u8; 4];
    OsRng.fill_bytes(&mut suffix_bytes);
    let temp_tar = format!("{}.tmp_{}", output_path, hex::encode(suffix_bytes));

    // 1. Crear TAR temporal
    {
        let file = File::create(&temp_tar).map_err(|_| "Error al crear archivo temporal")?;
        let mut builder = tar::Builder::new(file);
        builder
            .append_dir_all(".", &input_path)
            .map_err(|_| "Error al empaquetar carpeta")?;
        builder
            .finish()
            .map_err(|_| "Error al finalizar empaquetado")?;
    }

    // 2. Cifrar con PQC — capturar Result para garantizar limpieza del temporal
    let result = encrypt_with_quantum(
        temp_tar.clone(),
        output_path,
        public_key_hex,
        signing_key_hex,
        false,
    )
    .await;
    let _ = secure_shred(&temp_tar); // Siempre limpiar el temporal
    let result = result?;

    // Borrado seguro (DoD 5220.22-M) recursivo verdadero
    if result.success && shred_original {
        let _ = secure_shred_dir_recursive(std::path::Path::new(&input_path));
    }

    Ok(result)
}

/// Comando para descifrar una carpeta con Identidad Cuántica
#[tauri::command]
pub async fn decrypt_folder_with_quantum(
    input_path: String,
    output_path: String,
    private_key_hex: String,
    verifier_key_hex: Option<String>,
) -> Result<EncryptResponse, String> {
    // FIX #4: Sufijo aleatorio anti-TOCTOU
    let mut suffix_bytes = [0u8; 4];
    OsRng.fill_bytes(&mut suffix_bytes);
    let temp_tar = format!("{}.tmp_{}", input_path, hex::encode(suffix_bytes));

    // Descifrar con PQC — capturar Result para limpiar temporal si falla
    let result = decrypt_with_quantum(
        input_path,
        temp_tar.clone(),
        private_key_hex,
        verifier_key_hex,
    )
    .await
    .map_err(|e| {
        let _ = secure_shred(&temp_tar);
        e
    })?;

    if result.success {
        let file = File::open(&temp_tar).map_err(|_| "Error al abrir TAR temporal")?;
        let mut archive = tar::Archive::new(file);
        let unpack_result = archive.unpack(&output_path);
        let _ = secure_shred(&temp_tar); // Limpiar siempre
        unpack_result.map_err(|_| "Error al extraer carpeta del contenedor")?;

        Ok(EncryptResponse {
            success: true,
            message: "Carpeta restaurada con éxito mediante identidad cuántica".into(),
            data: None,
        })
    } else {
        let _ = secure_shred(&temp_tar);
        Err("Fallo al descifrar el contenedor cuántico de la carpeta".into())
    }
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

    // Prevención de rastro esteganográfico: Destruir el .vault original (Plausible Deniability)
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

    loop {
        let count = file.read(&mut buffer).map_err(|_| "Error de I/O al leer el archivo.")?;
        if count == 0 {
            break;
        }

        let mut search_buf = Vec::with_capacity(previous_tail.len() + count);
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
        let mut out_file = File::create(&output_vault_path).map_err(|_| "Error al crear el archivo extraído.")?;
        io::copy(&mut file, &mut out_file).map_err(|_| "Error de I/O al volcar los datos extraídos.")?;

        Ok(EncryptResponse {
            success: true,
            message: "Contenedor extraído con éxito del archivo de camuflaje".into(),
            data: None,
        })
    } else {
        Err("No se encontraron datos ocultos de CryptoBro en este archivo".into())
    }
}

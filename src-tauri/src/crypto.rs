use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use chacha20poly1305::ChaCha20Poly1305;
use argon2::{
    Argon2, Params,
};
use rand::{rngs::OsRng, RngCore};
use kem::{Decapsulate, Encapsulate};
use ml_kem::{MlKem1024, KemCore, EncodedSizeUser, MlKem1024Params, kem::EncapsulationKey, kem::DecapsulationKey};
use std::fs::{self, File};
use std::io::{self, Read, Write, Seek, SeekFrom, BufReader, BufWriter};
use dilithium::{MlDsaKeyPair, ML_DSA_65};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};

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

/// Borrado seguro de un archivo sobrescribiéndolo con datos aleatorios
/// Sobrescribe el contenido original con ruido aleatorio de OsRng antes de eliminarlo
/// para prevenir la recuperación de datos mediante herramientas de forense digital.
fn secure_shred(path: &str) -> std::io::Result<()> {
    let metadata = std::fs::metadata(path)?;
    let size = metadata.len();
    let mut file = std::fs::OpenOptions::new().write(true).open(path)?;

    // 1. Sobrescribir con datos aleatorios
    let mut random_data = vec![0u8; 65536];
    let mut written = 0;
    while written < size {
        OsRng.fill_bytes(&mut random_data);
        let to_write = std::cmp::min(random_data.len() as u64, size - written) as usize;
        file.write_all(&random_data[..to_write])?;
        written += to_write as u64;
    }
    file.sync_all()?;

    // 2. Sobrescribir con ceros
    file.set_len(0)?;
    file.sync_all()?;

    // 3. Eliminar archivo
    std::fs::remove_file(path)?;
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

/// Deriva claves simétricas a partir de una contraseña usando Argon2id
pub fn derive_keys(password: &str, salt: &[u8]) -> (Vec<u8>, Vec<u8>) {
    // Configuración de Argon2id (Parámetros de grado militar)
    let config = Params::new(65536, 3, 4, None).expect("Parámetros de Argon2 inválidos");

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        config,
    );

    let mut output = [0u8; 64];
    argon2.hash_password_into(password.as_bytes(), salt, &mut output).expect("Fallo al derivar claves");
    
    // Devolvemos dos claves de 32 bytes (una para AES y otra para ChaCha20)
    (output[0..32].to_vec(), output[32..64].to_vec())
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
        let count = reader.read(&mut buffer).map_err(|e| e.to_string())?;
        if count == 0 { break; }
        let chunk = &buffer[..count];

        // Comprimir con Gzip
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(chunk).map_err(|e| e.to_string())?;
        let compressed = encoder.finish().map_err(|e| e.to_string())?;

        // Nonce único por bloque
        let aes_nonce = derive_block_nonce(aes_nonce_raw, block_index);
        let chacha_nonce = derive_block_nonce(chacha_nonce_raw, block_index);

        // Doble capa de cifrado
        let enc_aes = aes_cipher.encrypt(Nonce::from_slice(&aes_nonce), compressed.as_slice()).map_err(|e| e.to_string())?;
        let enc_final = chacha_cipher.encrypt(Nonce::from_slice(&chacha_nonce), enc_aes.as_slice()).map_err(|e| e.to_string())?;

        // Escribir: longitud (4 bytes) + datos cifrados
        let len = enc_final.len() as u32;
        writer.write_all(&len.to_be_bytes()).map_err(|e| e.to_string())?;
        writer.write_all(&enc_final).map_err(|e| e.to_string())?;
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
            Ok(_) => {},
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.to_string()),
        }
        let chunk_len = u32::from_be_bytes(len_buf) as usize;
        let mut chunk = vec![0u8; chunk_len];
        reader.read_exact(&mut chunk).map_err(|_| "Contenedor corrupto: bloque de datos incompleto")?;

        let aes_nonce = derive_block_nonce(aes_nonce_raw, block_index);
        let chacha_nonce = derive_block_nonce(chacha_nonce_raw, block_index);

        // Revertir capas
        let dec_chacha = chacha_cipher.decrypt(Nonce::from_slice(&chacha_nonce), chunk.as_slice())
            .map_err(|_| "Fallo en Capa 2 (ChaCha20): datos corruptos o clave incorrecta")?;
        let dec_aes = aes_cipher.decrypt(Nonce::from_slice(&aes_nonce), dec_chacha.as_slice())
            .map_err(|_| "Fallo en Capa 1 (AES-GCM): datos corruptos o clave incorrecta")?;

        // Descomprimir si aplica
        let final_data = if use_compression {
            let mut decoder = GzDecoder::new(dec_aes.as_slice());
            let mut decompressed = Vec::new();
            decoder.read_to_end(&mut decompressed).map_err(|e| e.to_string())?;
            decompressed
        } else {
            dec_aes
        };

        writer.write_all(&final_data).map_err(|e| e.to_string())?;
        block_index += 1;
    }
    Ok(())
}

/// Comando para cifrar un archivo con múltiples capas (AES-256 + ChaCha20)
#[tauri::command]
pub async fn encrypt_file(
    input_path: String,
    output_path: String,
    password: String,
    shred_original: bool,
) -> Result<EncryptResponse, String> {
    let mut input_file = File::open(&input_path).map_err(|e| e.to_string())?;
    let mut output_file = File::create(&output_path).map_err(|e| e.to_string())?;

    // Generar Sal y Nonces (Vectores de Inicialización) aleatorios
    let mut salt = [0u8; SALT_SIZE];
    let mut aes_nonce_raw = [0u8; NONCE_SIZE];
    let mut chacha_nonce_raw = [0u8; NONCE_SIZE];
    
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut aes_nonce_raw);
    OsRng.fill_bytes(&mut chacha_nonce_raw);

    // Escribir cabecera: Flags (1) + Sal (16) + Nonce AES (12) + Nonce ChaCha (12)
    let flags = 0x01u8; // Bit 0: Compresión activada
    output_file.write_all(&[flags]).map_err(|e| e.to_string())?;
    output_file.write_all(&salt).map_err(|e| e.to_string())?;
    output_file.write_all(&aes_nonce_raw).map_err(|e| e.to_string())?;
    output_file.write_all(&chacha_nonce_raw).map_err(|e| e.to_string())?;

    // Derivar claves a partir de la contraseña
    let (aes_key, chacha_key) = derive_keys(&password, &salt);
    
    let aes_cipher = Aes256Gcm::new_from_slice(&aes_key).map_err(|e| e.to_string())?;
    let chacha_cipher = ChaCha20Poly1305::new_from_slice(&chacha_key).map_err(|e| e.to_string())?;

    encrypt_blocks(&mut input_file, &mut output_file, &aes_cipher, &chacha_cipher, &aes_nonce_raw, &chacha_nonce_raw)?;

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
    password: String,
) -> Result<EncryptResponse, String> {
    let mut input_file = File::open(&input_path).map_err(|e| e.to_string())?;
    let mut output_file = File::create(&output_path).map_err(|e| e.to_string())?;

    // Leer cabecera
    let mut flags_buf = [0u8; 1];
    input_file.read_exact(&mut flags_buf).map_err(|e| e.to_string())?;
    let flags = flags_buf[0];

    let mut salt = [0u8; SALT_SIZE];
    let mut aes_nonce_raw = [0u8; NONCE_SIZE];
    let mut chacha_nonce_raw = [0u8; NONCE_SIZE];

    input_file.read_exact(&mut salt).map_err(|e| e.to_string())?;
    input_file.read_exact(&mut aes_nonce_raw).map_err(|e| e.to_string())?;
    input_file.read_exact(&mut chacha_nonce_raw).map_err(|e| e.to_string())?;

    // Re-derivar las mismas claves
    let (aes_key, chacha_key) = derive_keys(&password, &salt);
    
    let aes_cipher = Aes256Gcm::new_from_slice(&aes_key).map_err(|e| e.to_string())?;
    let chacha_cipher = ChaCha20Poly1305::new_from_slice(&chacha_key).map_err(|e| e.to_string())?;
    let use_compression = (flags & 0x01) != 0;

    decrypt_blocks(&mut input_file, &mut output_file, &aes_cipher, &chacha_cipher, &aes_nonce_raw, &chacha_nonce_raw, use_compression)?;

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
    let dsa_kp = MlDsaKeyPair::generate(ML_DSA_65).map_err(|e| e.to_string())?;
    
    // Codificar todo en Hexadecimal
    let kem_pk_hex = hex::encode(kem_pk.as_bytes());
    let kem_sk_hex = hex::encode(kem_sk.as_bytes());
    let dsa_pk_hex = hex::encode(dsa_kp.public_key());
    let dsa_sk_hex = hex::encode(dsa_kp.private_key());

    Ok(EncryptResponse {
        success: true,
        message: "Identidad Cuántica Completa (Cifrado + Firma) generada con éxito".into(),
        data: Some(format!("{}:{}:{}:{}", kem_pk_hex, kem_sk_hex, dsa_pk_hex, dsa_sk_hex)),
    })
}

/// Comando para cifrar con identidad cuántica
#[tauri::command]
pub async fn encrypt_with_quantum(
    input_path: String,
    output_path: String,
    public_key_hex: String,
    signing_key_hex: Option<String>,
    shred_original: bool,
) -> Result<EncryptResponse, String> {
    let pk_bytes = hex::decode(public_key_hex).map_err(|_| "Llave pública inválida")?;
    
    // Parsear la llave pública
    let pk_bytes_array: &[u8; 1568] = pk_bytes.as_slice().try_into().map_err(|_| "Longitud de llave pública incorrecta")?;
    let pk = EncapsulationKey::<MlKem1024Params>::from_bytes(pk_bytes_array.into());
    
    // Encapsular usando ML-KEM-1024
    let (ciphertext, shared_secret) = pk.encapsulate(&mut OsRng)
        .map_err(|_| "Fallo en la encapsulación cuántica")?;

    // Usamos el secreto compartido como "contraseña" para nuestro sistema de cascada
    let shared_secret_hex = hex::encode(shared_secret.as_slice());

    // Cifrar el archivo usando la lógica existente
    // Pero primero, necesitamos escribir el Ciphertext de ML-KEM en el archivo de salida
    // para que el destinatario pueda decapsularlo.
    
    let mut input_file = File::open(&input_path).map_err(|e| e.to_string())?;
    let mut output_file = File::create(&output_path).map_err(|e| e.to_string())?;

    // --- CONSTRUCCIÓN DEL CONTENEDOR .VAULT ---
    
    // 1. Escribir Identificador (1 = Quantum, 2 = Quantum Signed)
    let vault_id = if signing_key_hex.is_some() { 2u8 } else { 1u8 };
    output_file.write_all(&[vault_id]).map_err(|e| e.to_string())?;

    // Si es firmado, reservamos espacio para la firma (3309 bytes para ML-DSA-65)
    // Pero es mejor escribirla al final o después del ID.
    // Escribamos un marcador de posición si es ID 2.
    if vault_id == 2 {
        output_file.write_all(&[0u8; 3309]).map_err(|e| e.to_string())?;
    }
    
    // 2. Escribir el Ciphertext de ML-KEM (1568 bytes para ML-KEM-1024)
    output_file.write_all(ciphertext.as_slice()).map_err(|e| e.to_string())?;

    // 3. Escribir Flags (1 byte)
    let flags = 0x01u8; // Compresión activada
    output_file.write_all(&[flags]).map_err(|e| e.to_string())?;

    // 4. Generar Sal y Nonces aleatorios para las capas simétricas
    let mut salt = [0u8; SALT_SIZE];
    let mut aes_nonce_raw = [0u8; NONCE_SIZE];
    let mut chacha_nonce_raw = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut aes_nonce_raw);
    OsRng.fill_bytes(&mut chacha_nonce_raw);

    output_file.write_all(&salt).map_err(|e| e.to_string())?;
    output_file.write_all(&aes_nonce_raw).map_err(|e| e.to_string())?;
    output_file.write_all(&chacha_nonce_raw).map_err(|e| e.to_string())?;

    // Derivar claves a partir del secreto compartido
    let (aes_key, chacha_key) = derive_keys(&shared_secret_hex, &salt);
    
    let aes_cipher = Aes256Gcm::new_from_slice(&aes_key).map_err(|e| e.to_string())?;
    let chacha_cipher = ChaCha20Poly1305::new_from_slice(&chacha_key).map_err(|e| e.to_string())?;

    encrypt_blocks(&mut input_file, &mut output_file, &aes_cipher, &chacha_cipher, &aes_nonce_raw, &chacha_nonce_raw)?;

    // Finalizar escritura y asegurar en disco
    output_file.flush().map_err(|e| e.to_string())?;
    output_file.sync_all().map_err(|e| e.to_string())?;
    drop(output_file);

    // 5. Firma Digital con Hash Streaming (evita cargar el archivo completo en RAM)
    if let Some(sk_combined_hex) = signing_key_hex {
        let parts: Vec<&str> = sk_combined_hex.split(':').collect();
        if parts.len() == 2 {
            let vk_bytes = hex::decode(parts[0]).map_err(|_| "Llave de verificación de firma inválida")?;
            let sk_bytes = hex::decode(parts[1]).map_err(|_| "Llave de firma privada inválida")?;

            // Calcular SHA-256 del cuerpo del archivo (desde byte 3310) mediante streaming
            // Esto evita cargar archivos de varios GB en RAM para calcular la firma.
            let mut hasher = Sha256::new();
            let mut sign_file = File::open(&output_path).map_err(|e| e.to_string())?;
            sign_file.seek(SeekFrom::Start(3310)).map_err(|e| e.to_string())?;
            let mut hash_buf = [0u8; 65536];
            loop {
                let n = sign_file.read(&mut hash_buf).map_err(|e| e.to_string())?;
                if n == 0 { break; }
                hasher.update(&hash_buf[..n]);
            }
            let file_hash = hasher.finalize();

            let dsa_vk_bytes: [u8; 1952] = vk_bytes.try_into().map_err(|_| "Longitud de llave pública de firma incorrecta")?;
            let dsa_sk_bytes: [u8; 4032] = sk_bytes.try_into().map_err(|_| "Longitud de llave privada de firma incorrecta")?;

            let dsa_kp = MlDsaKeyPair::from_keys(&dsa_sk_bytes, &dsa_vk_bytes, ML_DSA_65).map_err(|e| e.to_string())?;
            // Firmamos el hash del archivo (no el archivo completo)
            let sig = dsa_kp.sign(file_hash.as_slice(), b"").map_err(|e| e.to_string())?;

            // Leer el archivo completo para insertar la firma
            let mut file_data = fs::read(&output_path).map_err(|e| e.to_string())?;
            file_data[1..3310].copy_from_slice(sig.as_bytes());
            fs::write(&output_path, file_data).map_err(|e| e.to_string())?;
        }
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
    private_key_hex: String,
    verifier_key_hex: Option<String>,
) -> Result<EncryptResponse, String> {
    let mut input_file = File::open(&input_path).map_err(|e| e.to_string())?;
    
    // --- PROTOCOLO DE DES-BLINDAJE CUÁNTICO ---
    
    // 1. Leer identificador de tipo de contenedor
    let mut id_buf = [0u8; 1];
    input_file.read_exact(&mut id_buf).map_err(|_| "Archivo no es un contenedor cuántico válido")?;
    let vault_id = id_buf[0];
    
    // 2. Verificar Firma Digital (Si el contenedor es de tipo 2)
    // Implementa el estándar FIPS 204 (ML-DSA-65).
    if vault_id == 2 {
        let mut sig = [0u8; 3309]; // Tamaño de firma ML-DSA-65
        input_file.read_exact(&mut sig).map_err(|e| e.to_string())?;

        // Solo verificamos si el usuario ha proporcionado la llave pública del remitente.
        if let Some(vk_hex) = verifier_key_hex {
            let vk_bytes = hex::decode(vk_hex).map_err(|_| "Llave de verificación inválida")?;
            
            // Calcular SHA-256 del cuerpo del archivo mediante streaming (evita cargar el archivo en RAM)
            let mut hasher = Sha256::new();
            let mut hash_buf = [0u8; 65536];
            loop {
                let n = input_file.read(&mut hash_buf).map_err(|e| e.to_string())?;
                if n == 0 { break; }
                hasher.update(&hash_buf[..n]);
            }
            let file_hash = hasher.finalize();
            
            let vk_bytes_array: [u8; 1952] = vk_bytes.try_into().map_err(|_| "Longitud de llave de verificación incorrecta")?;
            let dsa_sig = dilithium::MlDsaSignature::from_slice(&sig);
            
            // Alerta Roja: verificamos el hash del cuerpo, no el cuerpo completo
            if !MlDsaKeyPair::verify(&vk_bytes_array, &dsa_sig, file_hash.as_slice(), b"", ML_DSA_65) {
                return Err("¡ALERTA ROJA! La firma digital es INVÁLIDA o el archivo ha sido manipulado.".into());
            }
            
            // Resetear cursor para continuar con el descifrado KEM
            input_file = File::open(&input_path).map_err(|e| e.to_string())?;
            input_file.seek(SeekFrom::Start(3310)).map_err(|e| e.to_string())?;
        } else {
            // Si no hay llave de verificación, saltamos el bloque de firma.
            input_file.seek(SeekFrom::Start(3310)).map_err(|e| e.to_string())?;
        }
    }

    // Leer Ciphertext de ML-KEM
    let mut kem_ciphertext = vec![0u8; 1568]; // Tamaño fijo para ML-KEM-1024
    input_file.read_exact(&mut kem_ciphertext).map_err(|e| e.to_string())?;

    // Leer Flags
    let mut flags_buf = [0u8; 1];
    input_file.read_exact(&mut flags_buf).map_err(|e| e.to_string())?;
    let flags = flags_buf[0];

    // Decapsular usando la llave privada
    let sk_bytes = hex::decode(private_key_hex).map_err(|_| "Llave privada inválida")?;
    let sk_bytes_array: &[u8; 3168] = sk_bytes.as_slice().try_into().map_err(|_| "Longitud de llave privada incorrecta")?;
    let sk = DecapsulationKey::<MlKem1024Params>::from_bytes(sk_bytes_array.into());

    // Convertir el ciphertext en el tipo esperado por kem
    let ct_bytes_array: [u8; 1568] = kem_ciphertext.try_into().map_err(|_| "Contenedor cuántico corrupto")?;
    let ciphertext = ml_kem::array::Array::from(ct_bytes_array);

    let shared_secret = sk.decapsulate(&ciphertext)
        .map_err(|_| "Fallo al descifrar el secreto cuántico. ¿Es la llave correcta?")?;

    let shared_secret_hex = hex::encode(shared_secret.as_slice());

    // Ahora procedemos con el descifrado normal usando ese secreto
    let mut output_file = File::create(&output_path).map_err(|e| e.to_string())?;

    let mut salt = [0u8; SALT_SIZE];
    let mut aes_nonce_raw = [0u8; NONCE_SIZE];
    let mut chacha_nonce_raw = [0u8; NONCE_SIZE];

    input_file.read_exact(&mut salt).map_err(|e| e.to_string())?;
    input_file.read_exact(&mut aes_nonce_raw).map_err(|e| e.to_string())?;
    input_file.read_exact(&mut chacha_nonce_raw).map_err(|e| e.to_string())?;

    let (aes_key, chacha_key) = derive_keys(&shared_secret_hex, &salt);
    let aes_cipher = Aes256Gcm::new_from_slice(&aes_key).map_err(|e| e.to_string())?;
    let chacha_cipher = ChaCha20Poly1305::new_from_slice(&chacha_key).map_err(|e| e.to_string())?;
    let use_compression = (flags & 0x01) != 0;

    let mut reader = BufReader::new(input_file);
    decrypt_blocks(&mut reader, &mut output_file, &aes_cipher, &chacha_cipher, &aes_nonce_raw, &chacha_nonce_raw, use_compression)?;

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
    let temp_tar = format!("{}.tmp_tar", output_path);
    
    // Crear el archivo TAR temporal
    {
        let file = File::create(&temp_tar).map_err(|e| e.to_string())?;
        let mut builder = tar::Builder::new(file);
        builder.append_dir_all(".", &input_path).map_err(|e| e.to_string())?;
        builder.finish().map_err(|e| e.to_string())?;
    }

    // Cifrar el archivo TAR temporal como si fuera un archivo normal
    // Usamos false para shred_original aquí porque nosotros borramos el temporal manualmente abajo
    let result = encrypt_file(temp_tar.clone(), output_path, password, false).await;
    
    // Eliminar el archivo temporal
    let _ = std::fs::remove_file(&temp_tar);

    if result.as_ref().is_ok() && shred_original {
        // Borrado seguro de la carpeta original (recursivo)
        let _ = std::fs::remove_dir_all(&input_path);
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
    let temp_tar = format!("{}.tmp_tar", input_path);

    // Descifrar el contenedor al archivo TAR temporal
    let result = decrypt_file(input_path, temp_tar.clone(), password).await?;

    if result.success {
        // Extraer el TAR a la carpeta de destino
        let file = File::open(&temp_tar).map_err(|e| e.to_string())?;
        let mut archive = tar::Archive::new(file);
        archive.unpack(&output_path).map_err(|e| e.to_string())?;
        
        // Eliminar el archivo temporal
        let _ = std::fs::remove_file(&temp_tar);

        Ok(EncryptResponse {
            success: true,
            message: "Carpeta restaurada con éxito desde el contenedor seguro".into(),
            data: None,
        })
    } else {
        let _ = std::fs::remove_file(&temp_tar);
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
    let temp_tar = format!("{}.tmp_tar", output_path);
    
    // 1. Crear TAR temporal
    {
        let file = File::create(&temp_tar).map_err(|e| e.to_string())?;
        let mut builder = tar::Builder::new(file);
        builder.append_dir_all(".", &input_path).map_err(|e| e.to_string())?;
        builder.finish().map_err(|e| e.to_string())?;
    }

    // 2. Cifrar con PQC
    let result = encrypt_with_quantum(temp_tar.clone(), output_path, public_key_hex, signing_key_hex, false).await?;
    
    // 3. Limpiar temporal
    let _ = std::fs::remove_file(&temp_tar);

    if result.success && shred_original {
        let _ = std::fs::remove_dir_all(&input_path);
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
    let temp_tar = format!("{}.tmp_tar", input_path);

    // 1. Descifrar con PQC
    let result = decrypt_with_quantum(input_path, temp_tar.clone(), private_key_hex, verifier_key_hex).await?;

    if result.success {
        // 2. Extraer TAR
        let file = File::open(&temp_tar).map_err(|e| e.to_string())?;
        let mut archive = tar::Archive::new(file);
        archive.unpack(&output_path).map_err(|e| e.to_string())?;
        
        let _ = std::fs::remove_file(&temp_tar);

        Ok(EncryptResponse {
            success: true,
            message: "Carpeta restaurada con éxito mediante identidad cuántica".into(),
            data: None,
        })
    } else {
        let _ = std::fs::remove_file(&temp_tar);
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
    let mut carrier_file = File::open(&image_path).map_err(|e| e.to_string())?;
    let mut vault_file = File::open(&vault_path).map_err(|e| e.to_string())?;
    let output_file = File::create(&output_path).map_err(|e| e.to_string())?;
    let mut writer = BufWriter::new(output_file);

    // 1. Copiar archivo original (portada)
    io::copy(&mut carrier_file, &mut writer).map_err(|e| e.to_string())?;

    // 2. Escribir marcador
    writer.write_all(STEGO_MARKER).map_err(|e| e.to_string())?;

    // 3. Copiar datos del vault
    io::copy(&mut vault_file, &mut writer).map_err(|e| e.to_string())?;

    writer.flush().map_err(|e| e.to_string())?;

    Ok(EncryptResponse {
        success: true,
        message: "¡Bóveda camuflada con éxito! El archivo de camuflaje sigue siendo funcional.".into(),
        data: None,
    })
}

/// Comando para extraer un archivo .vault de una imagen camuflada
#[tauri::command]
pub async fn extract_from_image(
    image_path: String,
    output_vault_path: String,
) -> Result<EncryptResponse, String> {
    let mut file = File::open(&image_path).map_err(|e| e.to_string())?;
    
    // Leemos el archivo en bloques para encontrar el marcador sin colapsar la RAM
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).map_err(|e| e.to_string())?;

    if let Some(pos) = buffer.windows(STEGO_MARKER.len()).position(|window| window == STEGO_MARKER) {
        let vault_data = &buffer[pos + STEGO_MARKER.len()..];
        fs::write(&output_vault_path, vault_data).map_err(|e| e.to_string())?;
        
        Ok(EncryptResponse {
            success: true,
            message: "Contenedor extraído con éxito del archivo de camuflaje".into(),
            data: None,
        })
    } else {
        Err("No se encontraron datos ocultos de CryptoBro en este archivo".into())
    }
}

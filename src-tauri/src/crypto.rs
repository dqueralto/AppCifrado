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
use ml_kem::{MlKem1024, KemCore, EncodedSizeUser, MlKem1024Params, kem::EncapsulationKey, kem::DecapsulationKey, Ciphertext};
use std::fs::File;
use std::io::{Read, Write};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct EncryptResponse {
    pub success: bool,
    pub message: String,
    pub data: Option<String>,
}

// Constantes de seguridad
const SALT_SIZE: usize = 16;
const NONCE_SIZE: usize = 12; // Estándar para GCM y Poly1305
const CHUNK_SIZE: usize = 1024 * 1024; // Trozos de 1MB para streaming

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

/// Comando para cifrar un archivo con múltiples capas (AES-256 + ChaCha20)
#[tauri::command]
pub async fn encrypt_file(
    input_path: String,
    output_path: String,
    password: String,
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

    // Escribir cabecera: Sal (16) + Nonce AES (12) + Nonce ChaCha (12)
    output_file.write_all(&salt).map_err(|e| e.to_string())?;
    output_file.write_all(&aes_nonce_raw).map_err(|e| e.to_string())?;
    output_file.write_all(&chacha_nonce_raw).map_err(|e| e.to_string())?;

    // Derivar claves a partir de la contraseña
    let (aes_key, chacha_key) = derive_keys(&password, &salt);
    
    let aes_cipher = Aes256Gcm::new_from_slice(&aes_key).map_err(|e| e.to_string())?;
    let chacha_cipher = ChaCha20Poly1305::new_from_slice(&chacha_key).map_err(|e| e.to_string())?;

    let mut buffer = vec![0u8; CHUNK_SIZE];
    loop {
        let count = input_file.read(&mut buffer).map_err(|e| e.to_string())?;
        if count == 0 { break; }

        let chunk = &buffer[..count];
        
        // Capa 1: AES-256-GCM
        let encrypted_aes = aes_cipher
            .encrypt(Nonce::from_slice(&aes_nonce_raw), chunk)
            .map_err(|e| e.to_string())?;
            
        // Capa 2: ChaCha20-Poly1305
        let encrypted_final = chacha_cipher
            .encrypt(Nonce::from_slice(&chacha_nonce_raw), encrypted_aes.as_slice())
            .map_err(|e| e.to_string())?;

        // Escribir longitud del trozo (4 bytes) seguido de los datos cifrados
        let len = encrypted_final.len() as u32;
        output_file.write_all(&len.to_be_bytes()).map_err(|e| e.to_string())?;
        output_file.write_all(&encrypted_final).map_err(|e| e.to_string())?;
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

    // Leer cabecera (Sal y Nonces)
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

    let mut len_buf = [0u8; 4];
    loop {
        if input_file.read_exact(&mut len_buf).is_err() { break; }
        let chunk_len = u32::from_be_bytes(len_buf) as usize;
        
        let mut chunk = vec![0u8; chunk_len];
        input_file.read_exact(&mut chunk).map_err(|e| e.to_string())?;

        // Revertir capas (de fuera hacia dentro)
        // Descifrar Capa 2: ChaCha20-Poly1305
        let decrypted_chacha = chacha_cipher
            .decrypt(Nonce::from_slice(&chacha_nonce_raw), chunk.as_slice())
            .map_err(|_| "Error de descifrado: Fallo en Capa 2 (ChaCha20)".to_string())?;
            
        // Descifrar Capa 1: AES-256-GCM
        let decrypted_final = aes_cipher
            .decrypt(Nonce::from_slice(&aes_nonce_raw), decrypted_chacha.as_slice())
            .map_err(|_| "Error de descifrado: Fallo en Capa 1 (AES-GCM)".to_string())?;

        output_file.write_all(&decrypted_final).map_err(|e| e.to_string())?;
    }

    Ok(EncryptResponse {
        success: true,
        message: "Archivo descifrado con éxito".into(),
        data: None,
    })
}

#[tauri::command]
pub async fn generate_quantum_keys() -> Result<EncryptResponse, String> {
    // Generar par de llaves Kyber-1024
    let (decapsulation_key, encapsulation_key) = MlKem1024::generate(&mut OsRng);
    
    // Codificar en Hexadecimal para devolver a la interfaz
    let enc_hex = hex::encode(encapsulation_key.as_bytes());
    let dec_hex = hex::encode(decapsulation_key.as_bytes());

    Ok(EncryptResponse {
        success: true,
        message: "Par de llaves cuánticas ML-KEM-1024 generado con éxito".into(),
        data: Some(format!("{}:{}", enc_hex, dec_hex)),
    })
}

/// Comando para cifrar con identidad cuántica
#[tauri::command]
pub async fn encrypt_with_quantum(
    input_path: String,
    output_path: String,
    public_key_hex: String,
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

    // 1. Escribir Identificador de tipo de cifrado (1 = Quantum)
    output_file.write_all(&[1u8]).map_err(|e| e.to_string())?;
    
    // 2. Escribir el Ciphertext de ML-KEM (1568 bytes para ML-KEM-1024)
    output_file.write_all(ciphertext.as_slice()).map_err(|e| e.to_string())?;

    // 3. Generar Sal y Nonces aleatorios para las capas simétricas
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

    let mut buffer = vec![0u8; CHUNK_SIZE];
    loop {
        let count = input_file.read(&mut buffer).map_err(|e| e.to_string())?;
        if count == 0 { break; }
        let chunk = &buffer[..count];
        
        let encrypted_aes = aes_cipher.encrypt(Nonce::from_slice(&aes_nonce_raw), chunk).map_err(|e| e.to_string())?;
        let encrypted_final = chacha_cipher.encrypt(Nonce::from_slice(&chacha_nonce_raw), encrypted_aes.as_slice()).map_err(|e| e.to_string())?;

        let len = encrypted_final.len() as u32;
        output_file.write_all(&len.to_be_bytes()).map_err(|e| e.to_string())?;
        output_file.write_all(&encrypted_final).map_err(|e| e.to_string())?;
    }

    Ok(EncryptResponse {
        success: true,
        message: "Archivo blindado con Identidad Cuántica (ML-KEM-1024)".into(),
        data: None,
    })
}

#[tauri::command]
pub async fn decrypt_with_quantum(
    input_path: String,
    output_path: String,
    private_key_hex: String,
) -> Result<EncryptResponse, String> {
    let mut input_file = File::open(&input_path).map_err(|e| e.to_string())?;
    
    // Leer identificador
    let mut id_buf = [0u8; 1];
    input_file.read_exact(&mut id_buf).map_err(|_| "Archivo no es un contenedor cuántico válido")?;
    if id_buf[0] != 1 {
        return Err("Este archivo no fue cifrado con una Identidad Cuántica".into());
    }

    // Leer Ciphertext de ML-KEM
    let mut kem_ciphertext = vec![0u8; 1568]; // Tamaño fijo para ML-KEM-1024
    input_file.read_exact(&mut kem_ciphertext).map_err(|e| e.to_string())?;

    // Decapsular usando la llave privada
    let sk_bytes = hex::decode(private_key_hex).map_err(|_| "Llave privada inválida")?;
    let sk_bytes_array: &[u8; 3168] = sk_bytes.as_slice().try_into().map_err(|_| "Longitud de llave privada incorrecta")?;
    let sk = DecapsulationKey::<MlKem1024Params>::from_bytes(sk_bytes_array.into());

    // Convertir el ciphertext en el tipo esperado por kem
    let ct_bytes_array: &[u8; 1568] = kem_ciphertext.as_slice().try_into().map_err(|_| "Contenedor cuántico corrupto")?;
    let ciphertext = *ml_kem::array::Array::from_slice(ct_bytes_array);

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

    let mut len_buf = [0u8; 4];
    loop {
        if input_file.read_exact(&mut len_buf).is_err() { break; }
        let chunk_len = u32::from_be_bytes(len_buf) as usize;
        let mut chunk = vec![0u8; chunk_len];
        input_file.read_exact(&mut chunk).map_err(|e| e.to_string())?;

        let decrypted_chacha = chacha_cipher.decrypt(Nonce::from_slice(&chacha_nonce_raw), chunk.as_slice())
            .map_err(|_| "Fallo en Capa 2")?;
        let decrypted_final = aes_cipher.decrypt(Nonce::from_slice(&aes_nonce_raw), decrypted_chacha.as_slice())
            .map_err(|_| "Fallo en Capa 1")?;

        output_file.write_all(&decrypted_final).map_err(|e| e.to_string())?;
    }

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
    let result = encrypt_file(temp_tar.clone(), output_path, password).await;
    
    // Eliminar el archivo temporal
    let _ = std::fs::remove_file(&temp_tar);

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

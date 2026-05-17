use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{Argon2, Params};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Manager};
use zeroize::{Zeroize, Zeroizing};


// --- Protección contra fuerza bruta ---
// Almacena el número de intentos fallidos y el momento del primer fallo.
// Se reinicia si pasan más de 30 segundos desde el último intento fallido.
static FAILED_ATTEMPTS: std::sync::LazyLock<Mutex<HashMap<String, (u32, Instant)>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

const MAX_ATTEMPTS: u32 = 5;
const LOCKOUT_DURATION: Duration = Duration::from_secs(30);

fn check_and_register_attempt(key: &str, success: bool) -> Result<(), String> {
    let mut map = FAILED_ATTEMPTS.lock().map_err(|_| "Error interno: Fallo al acceder al registro de seguridad")?;

    if success {
        map.remove(key);
        return Ok(());
    }

    let entry = map.entry(key.to_string()).or_insert((0, Instant::now()));

    // Resetear si el bloqueo ha expirado
    if entry.1.elapsed() > LOCKOUT_DURATION {
        *entry = (0, Instant::now());
    }

    entry.0 += 1;

    if entry.0 >= MAX_ATTEMPTS {
        let remaining = LOCKOUT_DURATION
            .checked_sub(entry.1.elapsed())
            .unwrap_or(Duration::ZERO);
        return Err(format!(
            "Demasiados intentos fallidos. Espera {} segundos antes de intentarlo de nuevo.",
            remaining.as_secs()
        ));
    }

    Err(format!(
        "Contraseña incorrecta. Intentos restantes: {}",
        MAX_ATTEMPTS - entry.0
    ))
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Contact {
    pub name: String,
    pub public_key: String,
    #[serde(default)]
    pub verifier_key: String,
}

#[derive(Serialize, Deserialize)]
struct EncryptedStore {
    pub salt: String,
    pub nonce: String,
    pub data: String,
}

fn get_contacts_path(app: &AppHandle) -> Result<PathBuf, String> {
    let mut path = app
        .path()
        .app_config_dir()
        .map_err(|_| "No se pudo encontrar el directorio de configuración del sistema")?;
    if !path.exists() {
        let _ = fs::create_dir_all(&path);
    }
    path.push("contacts.vault");
    Ok(path)
}

/// Deriva la clave AES-256 para el vault de contactos usando Argon2id.
/// Devuelve la clave envuelta en `Zeroizing` para que se borre automáticamente
/// de la RAM al salir del ámbito (consistente con el resto del proyecto).
fn derive_key(password: &str, salt: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    let config = Params::new(65536, 3, 4, None).expect("Parámetros de Argon2 inválidos");
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, config);
    let _ = argon2.hash_password_into(password.as_bytes(), salt, key.as_mut());
    key
}

/// Lee y descifra los contactos del disco. Función interna que devuelve los
/// contactos junto con los parámetros de cifrado para reutilización.
fn load_contacts_internal(path: &PathBuf, password: &str) -> Result<Vec<Contact>, String> {
    if !path.exists() {
        return Ok(vec![]);
    }

    // Verificar si está bloqueado antes de intentar
    {
        let map = FAILED_ATTEMPTS.lock().map_err(|_| "Error interno: Fallo al acceder al registro de seguridad")?;
        if let Some((attempts, since)) = map.get("contacts") {
            if *attempts >= MAX_ATTEMPTS && since.elapsed() < LOCKOUT_DURATION {
                let remaining = LOCKOUT_DURATION
                    .checked_sub(since.elapsed())
                    .unwrap_or(Duration::ZERO);
                return Err(format!(
                    "Libreta bloqueada. Espera {} segundos.",
                    remaining.as_secs()
                ));
            }
        }
    }

    let content = fs::read_to_string(path).map_err(|_| "Error de I/O al leer la libreta de contactos desde el disco")?;
    let store: EncryptedStore =
        serde_json::from_str(&content).map_err(|_| "Error al leer la bóveda de contactos")?;

    let salt = hex::decode(store.salt).map_err(|_| "Error interno: Salt corrupto en la bóveda de contactos")?;
    let nonce_bytes = hex::decode(store.nonce).map_err(|_| "Error interno: Nonce corrupto en la bóveda de contactos")?;
    let encrypted_data = hex::decode(store.data).map_err(|_| "Error interno: Datos cifrados corruptos")?;

    let key_bytes = derive_key(password, &salt);
    let cipher = Aes256Gcm::new_from_slice(key_bytes.as_ref()).map_err(|_| "Error al inicializar el motor de descifrado")?;

    let decrypted = cipher
        .decrypt(Nonce::from_slice(&nonce_bytes), encrypted_data.as_slice())
        .map_err(|_| {
            let _ = check_and_register_attempt("contacts", false);
            "Contraseña de contactos incorrecta"
        })?;

    // Descifrado exitoso: resetear contador
    let _ = check_and_register_attempt("contacts", true);

    let contacts: Vec<Contact> = serde_json::from_slice(&decrypted).map_err(|_| "Error al decodificar la estructura de contactos guardada")?;
    Ok(contacts)
}

/// Cifra y guarda los contactos en disco con salt y nonce nuevos.
fn encrypt_and_save(path: PathBuf, password: &str, contacts: &Vec<Contact>) -> Result<(), String> {
    let mut salt = [0u8; 16];
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce_bytes);

    let key_bytes = derive_key(password, &salt);
    let cipher = Aes256Gcm::new_from_slice(key_bytes.as_ref()).map_err(|_| "Error al inicializar el motor de cifrado")?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let json_data = serde_json::to_vec(contacts).map_err(|_| "Error al codificar la lista de contactos")?;
    let encrypted_data = cipher
        .encrypt(nonce, json_data.as_slice())
        .map_err(|_| "Fallo al cifrar los contactos")?;

    let store = EncryptedStore {
        salt: hex::encode(salt),
        nonce: hex::encode(nonce_bytes),
        data: hex::encode(encrypted_data),
    };

    let content = serde_json::to_string(&store).map_err(|_| "Error al serializar la bóveda de contactos")?;
    fs::write(path, content).map_err(|_| "Error de I/O al escribir la libreta de contactos en el disco")?;
    Ok(())
}

#[tauri::command]
pub fn get_contacts(app: AppHandle, password: Option<String>) -> Result<Vec<Contact>, String> {
    let path = get_contacts_path(&app)?;
    let pass = password.ok_or("Se requiere contraseña maestra para abrir la libreta")?;
    load_contacts_internal(&path, &pass)
}

/// Guarda un contacto y devuelve la lista actualizada para evitar
/// que el frontend tenga que llamar a get_contacts de nuevo (ahorra 1 derivación Argon2).
#[tauri::command]
pub fn save_contact(
    app: AppHandle,
    mut password: String,
    name: String,
    public_key: String,
    verifier_key: String,
) -> Result<Vec<Contact>, String> {
    let path = get_contacts_path(&app)?;

    let mut contacts = load_contacts_internal(&path, &password)?;

    contacts.retain(|c| c.name != name);
    contacts.push(Contact { name, public_key, verifier_key });

    encrypt_and_save(path, &password, &contacts)?;
    let result = contacts.clone();
    password.zeroize();
    Ok(result)
}

/// Elimina un contacto y devuelve la lista actualizada para evitar
/// que el frontend tenga que llamar a get_contacts de nuevo (ahorra 1 derivación Argon2).
#[tauri::command]
pub fn delete_contact(app: AppHandle, mut password: String, name: String) -> Result<Vec<Contact>, String> {
    let path = get_contacts_path(&app)?;
    let mut contacts = load_contacts_internal(&path, &password)?;
    contacts.retain(|c| c.name != name);
    encrypt_and_save(path, &password, &contacts)?;
    let result = contacts.clone();
    password.zeroize();
    Ok(result)
}

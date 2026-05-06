use serde::{Serialize, Deserialize};
use std::fs;
use tauri::{AppHandle, Manager};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Contact {
    pub name: String,
    pub public_key: String,
}

fn get_contacts_path(app: &AppHandle) -> std::path::PathBuf {
    let mut path = app.path().app_config_dir().expect("No se pudo encontrar el directorio de configuración");
    if !path.exists() {
        let _ = fs::create_dir_all(&path);
    }
    path.push("contacts.json");
    path
}

#[tauri::command]
pub fn get_contacts(app: AppHandle) -> Vec<Contact> {
    let path = get_contacts_path(&app);
    if let Ok(content) = fs::read_to_string(path) {
        serde_json::from_str(&content).unwrap_or_else(|_| vec![])
    } else {
        vec![]
    }
}

#[tauri::command]
pub fn save_contact(app: AppHandle, name: String, public_key: String) -> Result<(), String> {
    let path = get_contacts_path(&app);
    let mut contacts = get_contacts(app.clone());
    
    // Evitar duplicados por nombre
    contacts.retain(|c| c.name != name);
    contacts.push(Contact { name, public_key });
    
    let content = serde_json::to_string(&contacts).map_err(|e| e.to_string())?;
    fs::write(path, content).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub fn delete_contact(app: AppHandle, name: String) -> Result<(), String> {
    let path = get_contacts_path(&app);
    let mut contacts = get_contacts(app.clone());
    contacts.retain(|c| c.name != name);
    
    let content = serde_json::to_string(&contacts).map_err(|e| e.to_string())?;
    fs::write(path, content).map_err(|e| e.to_string())?;
    Ok(())
}

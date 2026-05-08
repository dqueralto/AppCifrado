mod contacts;
mod crypto;

use contacts::{delete_contact, get_contacts, save_contact};
use crypto::{
    decrypt_file, decrypt_folder, decrypt_folder_with_quantum, decrypt_with_quantum, encrypt_file,
    encrypt_folder, encrypt_folder_with_quantum, encrypt_with_quantum, extract_from_image,
    generate_quantum_keys, hide_in_image,
};
use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let window = app.get_webview_window("main").unwrap();

            // Ajustar al 90% del alto de la pantalla dinámicamente
            if let Ok(Some(monitor)) = window.primary_monitor() {
                let size = monitor.size();
                let scale_factor = monitor.scale_factor();

                // Calculamos el ancho físico (550 logical -> physical)
                let width = 550.0 * scale_factor;
                // Calculamos el alto al 90% de la pantalla física
                let height = size.height as f64 * 0.90;

                // Aplicamos el tamaño
                let _ = window.set_size(tauri::Size::Physical(tauri::PhysicalSize {
                    width: width as u32,
                    height: height as u32,
                }));

                // Centrar horizontalmente pero pegar al margen superior (y: 0)
                let _ = window.set_position(tauri::Position::Physical(tauri::PhysicalPosition {
                    x: ((size.width as f64 - width) / 2.0) as i32,
                    y: 0,
                }));
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            encrypt_file,
            decrypt_file,
            generate_quantum_keys,
            encrypt_folder,
            decrypt_folder,
            encrypt_with_quantum,
            decrypt_with_quantum,
            encrypt_folder_with_quantum,
            decrypt_folder_with_quantum,
            hide_in_image,
            extract_from_image,
            get_contacts,
            save_contact,
            delete_contact
        ])
        .run(tauri::generate_context!())
        .expect("Error crítico al ejecutar la aplicación Tauri");
}

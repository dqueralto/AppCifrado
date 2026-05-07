mod crypto;
mod contacts;

use crypto::{
    encrypt_file, decrypt_file, generate_quantum_keys, 
    encrypt_folder, decrypt_folder, 
    encrypt_with_quantum, decrypt_with_quantum,
    encrypt_folder_with_quantum, decrypt_folder_with_quantum,
    hide_in_image, extract_from_image
};
use contacts::{get_contacts, save_contact, delete_contact};
use tauri::Manager;
use window_vibrancy::{apply_vibrancy, NSVisualEffectMaterial};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let window = app.get_webview_window("main").unwrap();

            // Ajustar al 85% del alto de la pantalla dinámicamente y ampliar ancho para el nuevo layout
            if let Ok(Some(monitor)) = window.primary_monitor() {
                let size = monitor.size();
                let scale_factor = monitor.scale_factor();
                
                // Calculamos el ancho físico (1150 logical -> physical para el nuevo diseño ancho)
                let width = 1150.0 * scale_factor;
                // Calculamos el alto al 85% de la pantalla física
                let height = size.height as f64 * 0.85;
                
                // Aplicamos el tamaño
                let _ = window.set_size(tauri::Size::Physical(tauri::PhysicalSize {
                    width: width as u32,
                    height: height as u32,
                }));

                // Centrar horizontal y verticalmente
                let _ = window.set_position(tauri::Position::Physical(tauri::PhysicalPosition {
                    x: ((size.width as f64 - width) / 2.0) as i32,
                    y: ((size.height as f64 - height) / 2.0) as i32,
                }));
            }

            #[cfg(target_os = "macos")]
            apply_vibrancy(&window, NSVisualEffectMaterial::UnderWindowBackground, None, None)
                .expect("Unsupported platform! 'apply_vibrancy' is only supported on macOS");

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
        .expect("error while running tauri application");
}

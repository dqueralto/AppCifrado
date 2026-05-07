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

            // Ajustar a un diseño horizontal de escritorio (1100px de ancho)
            if let Ok(Some(monitor)) = window.primary_monitor() {
                let size = monitor.size();
                let scale_factor = monitor.scale_factor();
                
                // Ancho de escritorio: 1100px
                let width = 1100.0 * scale_factor;
                
                // Alto: 90% del monitor para evitar quedar bajo la barra de tareas/dock
                let height = (size.height as f64 * 0.9) as u32;
                
                let _ = window.set_size(tauri::Size::Physical(tauri::PhysicalSize {
                    width: width as u32,
                    height: height,
                }));

                // Centrar totalmente en la pantalla
                let _ = window.set_position(tauri::Position::Physical(tauri::PhysicalPosition {
                    x: ((size.width as f64 - width) / 2.0) as i32,
                    y: ((size.height as f64 - height as f64) / 2.0) as i32,
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

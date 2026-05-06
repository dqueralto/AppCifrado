mod crypto;

use crypto::{encrypt_file, decrypt_file, generate_quantum_keys, encrypt_folder, decrypt_folder, encrypt_with_quantum, decrypt_with_quantum};
use tauri::Manager;
use window_vibrancy::{apply_vibrancy, NSVisualEffectMaterial};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .setup(|app| {
            let window = app.get_webview_window("main").unwrap();

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
            decrypt_with_quantum
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

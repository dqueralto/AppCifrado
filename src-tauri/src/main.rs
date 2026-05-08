// Previene la apertura de una ventana de consola adicional en Windows para versiones de producción. ¡NO ELIMINAR!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    quantum_vault_lib::run()
}

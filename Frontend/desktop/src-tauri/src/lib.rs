use tauri::LogicalSize;

// 콘솔 창을 로그인 폼에 딱 맞는 작은 화면으로 축소
#[tauri::command]
fn set_window_login(window: tauri::Window) {
    let _ = window.set_resizable(true);
    let _ = window.set_min_size(Some(LogicalSize::new(360.0, 460.0)));
    let _ = window.set_size(LogicalSize::new(360.0, 460.0));
    let _ = window.set_resizable(false);
    let _ = window.center();
}

// 콘솔 창을 대시보드용 큰 화면으로 확장
#[tauri::command]
fn set_window_main(window: tauri::Window) {
    let _ = window.set_resizable(true);
    let _ = window.set_min_size(Some(LogicalSize::new(1024.0, 720.0)));
    let _ = window.set_size(LogicalSize::new(1440.0, 900.0));
    let _ = window.center();
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![set_window_login, set_window_main])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

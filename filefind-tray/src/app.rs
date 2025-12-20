//! Main application logic for the system tray.
//!
//! This module handles the tray icon, menu creation,
//! and event loop for the filefind tray application.

use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use tray_icon::menu::{AboutMetadata, Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{TrayIcon, TrayIconBuilder};

use filefind::{DaemonStateInfo, DaemonStatus, IpcClient};

use crate::icons;

/// Menu item identifiers.
mod menu_ids {
    pub const STATUS: &str = "status";
    pub const START: &str = "start";
    pub const STOP: &str = "stop";
    pub const RESCAN: &str = "rescan";
    pub const OPEN_CLI: &str = "open_cli";
    pub const QUIT: &str = "quit";
}

const UPDATE_INTERVAL: Duration = Duration::from_secs(3);

/// Run the tray application.
///
/// This function does not return under normal operation as it runs the event loop.
pub fn run() -> Result<()> {
    // Create the tray icon (must be done on the thread with the event loop)
    let tray_icon = create_tray_icon()?;

    // Create IPC client for daemon communication
    let ipc_client = IpcClient::new();

    // Track if we should quit
    let should_quit = Arc::new(AtomicBool::new(false));
    let quit_flag = should_quit.clone();

    // Initial status update
    update_tray_status(&tray_icon, &ipc_client);

    // Subscribe to menu events
    let menu_channel = MenuEvent::receiver();

    // Spawn a thread to periodically update status
    let status_quit = should_quit;
    std::thread::spawn(move || {
        while !status_quit.load(Ordering::Relaxed) {
            std::thread::sleep(UPDATE_INTERVAL);
        }
    });

    // Track last status update time
    let mut last_update = std::time::Instant::now();

    // Run the Windows message loop
    #[cfg(windows)]
    {
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            DispatchMessageW, GetMessageW, MSG, TranslateMessage, WM_QUIT,
        };

        let mut msg: MSG = unsafe { std::mem::zeroed() };

        loop {
            // Check for quit signal
            if quit_flag.load(Ordering::Relaxed) {
                break;
            }

            // Periodically update status
            if last_update.elapsed() >= UPDATE_INTERVAL {
                update_tray_status(&tray_icon, &ipc_client);
                last_update = std::time::Instant::now();
            }

            // Handle menu events (non-blocking)
            if let Ok(event) = menu_channel.try_recv() {
                handle_menu_event(&event.id.0, &tray_icon, &ipc_client, &quit_flag);
            }

            // Process Windows messages with a timeout
            // Use PeekMessage-style approach with GetMessage
            // SAFETY: GetMessageW is safe to call with valid pointers
            let result = unsafe { GetMessageW(&raw mut msg, std::ptr::null_mut(), 0, 0) };

            if result == 0 || result == -1 {
                // WM_QUIT received or error
                break;
            }

            if msg.message == WM_QUIT {
                break;
            }

            // SAFETY: TranslateMessage and DispatchMessageW are safe with valid MSG
            unsafe {
                TranslateMessage(&raw const msg);
                DispatchMessageW(&raw const msg);
            }
        }
    }

    #[cfg(not(windows))]
    {
        // Non-Windows: simple polling loop
        loop {
            if quit_flag.load(Ordering::Relaxed) {
                break;
            }

            // Periodically update status
            if last_update.elapsed() >= update_interval {
                update_tray_status(&tray_icon, &ipc_client);
                last_update = std::time::Instant::now();
            }

            // Handle menu events
            if let Ok(event) = menu_channel.try_recv() {
                handle_menu_event(&event.id.0, &tray_icon, &ipc_client, &quit_flag);
            }

            std::thread::sleep(Duration::from_millis(100));
        }
    }

    Ok(())
}

/// Handle a menu event.
fn handle_menu_event(menu_id: &str, tray_icon: &TrayIcon, ipc_client: &IpcClient, quit_flag: &AtomicBool) {
    match menu_id {
        menu_ids::START => {
            tracing::info!("Starting daemon...");
            if let Err(error) = start_daemon() {
                tracing::error!("Failed to start daemon: {}", error);
            }
            // Update status after a short delay
            std::thread::sleep(Duration::from_millis(500));
            update_tray_status(tray_icon, ipc_client);
        }
        menu_ids::STOP => {
            tracing::info!("Stopping daemon...");
            if let Err(error) = ipc_client.stop_daemon() {
                tracing::error!("Failed to stop daemon: {}", error);
            }
            // Update status after a short delay
            std::thread::sleep(Duration::from_millis(500));
            update_tray_status(tray_icon, ipc_client);
        }
        menu_ids::RESCAN => {
            tracing::info!("Triggering rescan...");
            if let Err(error) = ipc_client.rescan() {
                tracing::error!("Failed to trigger rescan: {}", error);
            }
        }
        menu_ids::OPEN_CLI => {
            tracing::info!("Opening CLI...");
            if let Err(error) = open_cli() {
                tracing::error!("Failed to open CLI: {}", error);
            }
        }
        menu_ids::QUIT => {
            tracing::info!("Quitting tray application");
            quit_flag.store(true, Ordering::Relaxed);

            #[cfg(windows)]
            {
                // Post WM_QUIT to exit the message loop
                use windows_sys::Win32::UI::WindowsAndMessaging::PostQuitMessage;
                // SAFETY: PostQuitMessage is always safe to call
                unsafe {
                    PostQuitMessage(0);
                }
            }
        }
        _ => {}
    }
}

/// Create the tray icon with menu.
fn create_tray_icon() -> Result<TrayIcon> {
    let icon = icons::create_stopped_icon()?;
    let menu = create_menu()?;

    let tray_icon = TrayIconBuilder::new()
        .with_icon(icon)
        .with_tooltip("Filefind - Stopped")
        .with_menu(Box::new(menu))
        .build()
        .context("Failed to build tray icon")?;

    Ok(tray_icon)
}

/// Create the tray menu.
fn create_menu() -> Result<Menu> {
    let menu = Menu::new();

    // Status item (disabled, shows current state)
    let status_item = MenuItem::with_id(menu_ids::STATUS, "Status: Unknown", false, None);

    // Control items
    let start_item = MenuItem::with_id(menu_ids::START, "Start daemon", true, None);
    let stop_item = MenuItem::with_id(menu_ids::STOP, "Stop daemon", true, None);
    let rescan_item = MenuItem::with_id(menu_ids::RESCAN, "Rescan", true, None);

    // Utility items
    let open_cli_item = MenuItem::with_id(menu_ids::OPEN_CLI, "Open Search CLI", true, None);

    // Quit item
    let quit_item = MenuItem::with_id(menu_ids::QUIT, "Quit", true, None);

    // About item
    let about_item = PredefinedMenuItem::about(
        Some("About Filefind"),
        Some(AboutMetadata {
            name: Some("Filefind".to_string()),
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
            authors: Some(vec!["Esgrove".to_string()]),
            comments: Some("Fast file indexing and search for Windows".to_string()),
            copyright: Some("MIT License".to_string()),
            license: Some("MIT".to_string()),
            website: Some("https://github.com/Esgrove/filefind".to_string()),
            website_label: Some("GitHub".to_string()),
            ..Default::default()
        }),
    );

    // Build the menu
    menu.append(&status_item)?;
    menu.append(&PredefinedMenuItem::separator())?;
    menu.append(&start_item)?;
    menu.append(&stop_item)?;
    menu.append(&rescan_item)?;
    menu.append(&PredefinedMenuItem::separator())?;
    menu.append(&open_cli_item)?;
    menu.append(&PredefinedMenuItem::separator())?;
    menu.append(&about_item)?;
    menu.append(&quit_item)?;

    Ok(menu)
}

/// Update the tray icon and tooltip based on daemon status.
fn update_tray_status(tray_icon: &TrayIcon, ipc_client: &IpcClient) {
    let status = get_daemon_status(ipc_client);

    // Update icon based on state
    let icon = match status.state {
        DaemonStateInfo::Running => icons::create_running_icon(),
        DaemonStateInfo::Scanning => icons::create_scanning_icon(),
        DaemonStateInfo::Starting | DaemonStateInfo::Stopping => icons::create_default_icon(),
        DaemonStateInfo::Stopped => icons::create_stopped_icon(),
    };

    if let Ok(icon) = icon {
        let _ = tray_icon.set_icon(Some(icon));
    }

    // Update tooltip
    let tooltip = format_status_tooltip(&status);
    let _ = tray_icon.set_tooltip(Some(tooltip));
}

/// Get the current daemon status.
fn get_daemon_status(ipc_client: &IpcClient) -> DaemonStatus {
    match ipc_client.get_status() {
        Ok(status) => status,
        Err(error) => {
            tracing::warn!("Failed to get daemon status: {}", error);
            DaemonStatus::default()
        }
    }
}

/// Format the status for the tooltip.
fn format_status_tooltip(status: &DaemonStatus) -> String {
    match status.state {
        DaemonStateInfo::Running => {
            format!(
                "Filefind - Running\nFiles: {}\nDirectories: {}",
                format_number(status.indexed_files),
                format_number(status.indexed_directories)
            )
        }
        DaemonStateInfo::Scanning => {
            format!("Filefind - Scanning...\nFiles: {}", format_number(status.indexed_files))
        }
        DaemonStateInfo::Starting => "Filefind - Starting...".to_string(),
        DaemonStateInfo::Stopping => "Filefind - Stopping...".to_string(),
        DaemonStateInfo::Stopped => "Filefind - Stopped".to_string(),
    }
}

/// Format a number with thousand separators.
fn format_number(number: u64) -> String {
    let string = number.to_string();
    let mut result = String::new();
    let chars: Vec<char> = string.chars().collect();
    let length = chars.len();

    for (index, char) in chars.iter().enumerate() {
        if index > 0 && (length - index).is_multiple_of(3) {
            result.push(',');
        }
        result.push(*char);
    }

    result
}

/// Start the daemon process.
fn start_daemon() -> Result<()> {
    #[cfg(windows)]
    {
        Command::new("cmd")
            .args(["/C", "start", "", "filefindd", "start", "-f"])
            .spawn()
            .context("Failed to start daemon process")?;
    }

    #[cfg(not(windows))]
    {
        Command::new("filefindd")
            .args(["start", "-f"])
            .spawn()
            .context("Failed to start daemon process")?;
    }

    Ok(())
}

/// Open the CLI search tool.
fn open_cli() -> Result<()> {
    #[cfg(windows)]
    {
        Command::new("cmd")
            .args(["/C", "start", "", "cmd", "/K", "filefind"])
            .spawn()
            .context("Failed to open CLI")?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_number() {
        assert_eq!(format_number(0), "0");
        assert_eq!(format_number(999), "999");
        assert_eq!(format_number(1000), "1,000");
        assert_eq!(format_number(1_234_567), "1,234,567");
        assert_eq!(format_number(1_000_000_000), "1,000,000,000");
    }

    #[test]
    fn test_format_status_tooltip_stopped() {
        let status = DaemonStatus::default();
        let tooltip = format_status_tooltip(&status);
        assert!(tooltip.contains("Stopped"));
    }

    #[test]
    fn test_format_status_tooltip_running() {
        let status = DaemonStatus {
            state: DaemonStateInfo::Running,
            indexed_files: 12345,
            indexed_directories: 678,
            ..Default::default()
        };
        let tooltip = format_status_tooltip(&status);
        assert!(tooltip.contains("Running"));
        assert!(tooltip.contains("12,345"));
        assert!(tooltip.contains("678"));
    }

    #[test]
    fn test_format_status_tooltip_scanning() {
        let status = DaemonStatus {
            state: DaemonStateInfo::Scanning,
            indexed_files: 5000,
            ..Default::default()
        };
        let tooltip = format_status_tooltip(&status);
        assert!(tooltip.contains("Scanning"));
        assert!(tooltip.contains("5,000"));
    }
}

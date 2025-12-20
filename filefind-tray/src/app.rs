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

use filefind::{DaemonStateInfo, DaemonStatus, IpcClient, format_number};

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

const UPDATE_INTERVAL: Duration = Duration::from_secs(2);

/// Run the tray application.
///
/// This function does not return under normal operation as it runs the event loop.
pub fn run() -> Result<()> {
    tracing::info!("Starting tray application");

    // Create the tray icon (must be done on the thread with the event loop)
    let (tray_icon, status_item) = create_tray_icon()?;

    // Create IPC client for daemon communication
    let ipc_client = IpcClient::new();

    // Track if we should quit
    let should_quit = Arc::new(AtomicBool::new(false));
    let quit_flag = should_quit.clone();

    // Track previous state for change detection
    let mut previous_state: Option<DaemonStateInfo> = None;

    // Initial status update
    tracing::info!("Checking initial daemon status...");
    previous_state = update_tray_status(&tray_icon, &status_item, &ipc_client, previous_state);

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
                previous_state = update_tray_status(&tray_icon, &status_item, &ipc_client, previous_state);
                last_update = std::time::Instant::now();
            }

            // Handle menu events (non-blocking)
            if let Ok(event) = menu_channel.try_recv() {
                handle_menu_event(&event.id.0, &tray_icon, &status_item, &ipc_client, &quit_flag);
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
            if last_update.elapsed() >= UPDATE_INTERVAL {
                previous_state = update_tray_status(&tray_icon, &status_item, &ipc_client, previous_state);
                last_update = std::time::Instant::now();
            }

            // Handle menu events
            if let Ok(event) = menu_channel.try_recv() {
                handle_menu_event(&event.id.0, &tray_icon, &status_item, &ipc_client, &quit_flag);
            }

            std::thread::sleep(Duration::from_millis(100));
        }
    }

    Ok(())
}

/// Handle a menu event.
fn handle_menu_event(
    menu_id: &str,
    tray_icon: &TrayIcon,
    status_item: &MenuItem,
    ipc_client: &IpcClient,
    quit_flag: &AtomicBool,
) {
    match menu_id {
        menu_ids::START => {
            tracing::info!("Starting daemon...");
            if let Err(error) = start_daemon() {
                tracing::error!("Failed to start daemon: {}", error);
            }
            // Update status after a short delay
            std::thread::sleep(Duration::from_millis(500));
            update_tray_status(tray_icon, status_item, ipc_client, None);
        }
        menu_ids::STOP => {
            tracing::info!("Stopping daemon...");
            match ipc_client.stop_daemon() {
                Ok(()) => tracing::info!("Stop command sent successfully"),
                Err(error) => tracing::error!("Failed to stop daemon: {}", error),
            }
            // Update status after a short delay
            std::thread::sleep(Duration::from_millis(500));
            update_tray_status(tray_icon, status_item, ipc_client, None);
        }
        menu_ids::RESCAN => {
            tracing::info!("Triggering rescan...");
            match ipc_client.rescan() {
                Ok(()) => tracing::info!("Rescan command sent successfully"),
                Err(error) => tracing::error!("Failed to trigger rescan: {}", error),
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
fn create_tray_icon() -> Result<(TrayIcon, MenuItem)> {
    let icon = icons::create_stopped_icon()?;
    let (menu, status_item) = create_menu()?;

    let tray_icon = TrayIconBuilder::new()
        .with_icon(icon)
        .with_tooltip("Filefind - Stopped")
        .with_menu(Box::new(menu))
        .build()
        .context("Failed to build tray icon")?;

    Ok((tray_icon, status_item))
}

/// Create the tray menu.
///
/// Returns the menu and the status menu item so it can be updated later.
fn create_menu() -> Result<(Menu, MenuItem)> {
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

    Ok((menu, status_item))
}

/// Update the tray icon, tooltip, and menu status based on daemon status.
///
/// Returns the current state for tracking state changes.
#[allow(clippy::unnecessary_wraps)]
fn update_tray_status(
    tray_icon: &TrayIcon,
    status_item: &MenuItem,
    ipc_client: &IpcClient,
    previous_state: Option<DaemonStateInfo>,
) -> Option<DaemonStateInfo> {
    let status = get_daemon_status(ipc_client);
    let current_state = status.state;

    // Log state changes
    match previous_state {
        None => {
            // First successful status check
            tracing::info!(
                "Connected to daemon: state={:?}, files={}, directories={}",
                current_state,
                format_number(status.indexed_files),
                format_number(status.indexed_directories)
            );
        }
        Some(prev) if prev != current_state => {
            tracing::info!(
                "Daemon state changed: {:?} -> {:?} (files: {}, directories: {})",
                prev,
                current_state,
                format_number(status.indexed_files),
                format_number(status.indexed_directories)
            );
        }
        _ => {
            // No state change, log at trace level
            tracing::trace!(
                "Status update: {:?}, files={}, directories={}",
                current_state,
                status.indexed_files,
                status.indexed_directories
            );
        }
    }

    // Update icon based on state
    let icon = match current_state {
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

    // Update menu status item
    let status_text = format_status_menu_text(&status);
    status_item.set_text(status_text);

    Some(current_state)
}

/// Format the status for the menu item.
fn format_status_menu_text(status: &DaemonStatus) -> String {
    match status.state {
        DaemonStateInfo::Running => format!("Status: Running ({} files)", format_number(status.indexed_files)),
        DaemonStateInfo::Scanning => format!("Status: Scanning ({} files)", format_number(status.indexed_files)),
        DaemonStateInfo::Starting => "Status: Starting...".to_string(),
        DaemonStateInfo::Stopping => "Status: Stopping...".to_string(),
        DaemonStateInfo::Stopped => "Status: Stopped".to_string(),
    }
}

/// Get the current daemon status.
fn get_daemon_status(ipc_client: &IpcClient) -> DaemonStatus {
    match ipc_client.get_status() {
        Ok(status) => {
            tracing::trace!("Got daemon status: {:?}", status.state);
            status
        }
        Err(error) => {
            tracing::warn!("Failed to get daemon status (daemon may not be running): {}", error);
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

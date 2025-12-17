//! System tray application for filefind daemon.
//!
//! This provides a minimal system tray interface for controlling the filefind
//! daemon, including start/stop controls and status display.

// Hide console window on Windows release builds
#![cfg_attr(all(target_os = "windows", not(debug_assertions)), windows_subsystem = "windows")]

mod app;
mod icons;

use anyhow::Result;
use tracing_subscriber::EnvFilter;

fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("filefind_tray=info".parse()?))
        .init();

    tracing::info!("Starting filefind tray application");

    // Run the tray application
    app::run()
}

//! Tray icon resources.
//!
//! This module provides embedded icons for the tray application.
//! Icons are stored as raw RGBA data for cross-platform compatibility.

use anyhow::{Context, Result};
use tray_icon::Icon;

/// Icon size in pixels.
const ICON_SIZE: u32 = 32;

/// Create the default tray icon.
///
/// This creates a simple icon representing a file/search symbol.
pub fn create_default_icon() -> Result<Icon> {
    let rgba = create_default_icon_rgba();
    Icon::from_rgba(rgba, ICON_SIZE, ICON_SIZE).context("Failed to create tray icon")
}

/// Create an icon indicating the daemon is running.
pub fn create_running_icon() -> Result<Icon> {
    let rgba = create_running_icon_rgba();
    Icon::from_rgba(rgba, ICON_SIZE, ICON_SIZE).context("Failed to create running icon")
}

/// Create an icon indicating the daemon is stopped.
pub fn create_stopped_icon() -> Result<Icon> {
    let rgba = create_stopped_icon_rgba();
    Icon::from_rgba(rgba, ICON_SIZE, ICON_SIZE).context("Failed to create stopped icon")
}

/// Create an icon indicating the daemon is scanning.
pub fn create_scanning_icon() -> Result<Icon> {
    let rgba = create_scanning_icon_rgba();
    Icon::from_rgba(rgba, ICON_SIZE, ICON_SIZE).context("Failed to create scanning icon")
}

/// Generate RGBA data for the default icon (blue file icon).
fn create_default_icon_rgba() -> Vec<u8> {
    create_icon_with_color(0x42, 0x85, 0xF4, 0xFF) // Blue
}

/// Generate RGBA data for the running icon (green).
fn create_running_icon_rgba() -> Vec<u8> {
    create_icon_with_color(0x34, 0xA8, 0x53, 0xFF) // Green
}

/// Generate RGBA data for the stopped icon (gray).
fn create_stopped_icon_rgba() -> Vec<u8> {
    create_icon_with_color(0x9A, 0x9A, 0x9A, 0xFF) // Gray
}

/// Generate RGBA data for the scanning icon (orange/yellow).
fn create_scanning_icon_rgba() -> Vec<u8> {
    create_icon_with_color(0xFB, 0xBC, 0x05, 0xFF) // Orange/Yellow
}

/// Create an icon with a simple file/magnifying glass design in the specified color.
///
/// The icon is a 32x32 image with:
/// - A rounded rectangle representing a file/document
/// - A small circle in the corner representing a search/magnifying glass
fn create_icon_with_color(red: u8, green: u8, blue: u8, alpha: u8) -> Vec<u8> {
    let size = ICON_SIZE as usize;
    let mut rgba = vec![0u8; size * size * 4];

    // Pixels outside the shape stay transparent from the zero-initialized buffer
    for (index, pixel) in rgba.as_chunks_mut::<4>().0.iter_mut().enumerate() {
        if is_icon_pixel(index % size, index / size) {
            *pixel = [red, green, blue, alpha];
        }
    }

    rgba
}

/// Check if the pixel at (`x`, `y`) belongs to the file/magnifying glass shape.
fn is_icon_pixel(x: usize, y: usize) -> bool {
    // File body (rounded rectangle from 4,2 to 22,29)
    let in_file_body = (4..=22).contains(&x) && (6..=29).contains(&y);

    // File corner fold (triangle in top-right)
    let in_corner_fold = (16..=22).contains(&x) && (2..=8).contains(&y) && (x - 16) + (y - 2) <= 6;

    // File top (before the fold)
    let in_file_top = (4..16).contains(&x) && (2..6).contains(&y);

    // Magnifying glass circle (bottom-right area)
    let glass_center_x = 24.0_f32;
    let glass_center_y = 24.0_f32;
    let glass_radius = 6.0_f32;
    let distance_from_glass = ((x as f32) - glass_center_x).hypot((y as f32) - glass_center_y);
    let in_glass_ring = distance_from_glass >= glass_radius - 2.0 && distance_from_glass <= glass_radius;

    // Magnifying glass handle
    let in_glass_handle = (28..=31).contains(&x) && (28..=31).contains(&y) && x.abs_diff(y) <= 2;

    in_file_body || in_corner_fold || in_file_top || in_glass_ring || in_glass_handle
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icon_size() {
        let rgba = create_default_icon_rgba();
        let expected_size = (ICON_SIZE * ICON_SIZE * 4) as usize;
        assert_eq!(rgba.len(), expected_size);
    }

    #[test]
    fn test_create_default_icon() {
        let result = create_default_icon();
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_running_icon() {
        let result = create_running_icon();
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_stopped_icon() {
        let result = create_stopped_icon();
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_scanning_icon() {
        let result = create_scanning_icon();
        assert!(result.is_ok());
    }

    #[test]
    fn test_icons_have_transparency() {
        let rgba = create_default_icon_rgba();
        // Check that some pixels are transparent (alpha = 0)
        let has_transparent = rgba.chunks(4).any(|pixel| pixel[3] == 0);
        assert!(has_transparent, "Icon should have transparent pixels");

        // Check that some pixels are opaque (alpha = 255)
        let has_opaque = rgba.chunks(4).any(|pixel| pixel[3] == 255);
        assert!(has_opaque, "Icon should have opaque pixels");
    }

    #[test]
    fn test_is_icon_pixel_known_coordinates() {
        // Transparent corners
        assert!(!is_icon_pixel(0, 0));
        assert!(!is_icon_pixel(31, 0));
        assert!(!is_icon_pixel(0, 31));
        // File top, body, and corner fold
        assert!(is_icon_pixel(4, 2));
        assert!(is_icon_pixel(10, 15));
        assert!(is_icon_pixel(16, 2));
        assert!(!is_icon_pixel(23, 2));
        // Magnifying glass ring and handle
        assert!(is_icon_pixel(30, 24));
        assert!(!is_icon_pixel(24, 24));
        assert!(is_icon_pixel(31, 31));
        assert!(is_icon_pixel(29, 31));
        assert!(!is_icon_pixel(28, 31));
    }

    #[test]
    fn test_icon_pixels_match_shape_and_color() {
        let size = ICON_SIZE as usize;
        let rgba = create_icon_with_color(1, 2, 3, 4);

        for y in 0..size {
            for x in 0..size {
                let index = (y * size + x) * 4;
                let pixel = &rgba[index..index + 4];
                let expected: &[u8] = if is_icon_pixel(x, y) {
                    &[1, 2, 3, 4]
                } else {
                    &[0, 0, 0, 0]
                };
                assert_eq!(pixel, expected, "unexpected pixel at ({x}, {y})");
            }
        }
    }
}

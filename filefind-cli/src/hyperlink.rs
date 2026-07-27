//! Clickable terminal hyperlinks for search results.
//!
//! Terminals that understand the OSC 8 escape sequence render printed text as a link.
//! Clicking it (Ctrl+Click in Windows Terminal and Warp, Cmd+Click in iTerm2) hands the
//! URI to the operating system, which opens the file with its default application.
//!
//! Links use the `file` scheme by default. A different scheme can be configured to route
//! clicks to a custom protocol handler instead.

use std::borrow::Cow;
use std::env;
use std::fmt::Write;
use std::io::IsTerminal;

use filefind::config::HyperlinkMode;

/// Opening delimiter of an OSC 8 hyperlink sequence.
const HYPERLINK_START: &str = "\x1b]8;;";

/// String Terminator that closes an OSC 8 sequence.
const HYPERLINK_TERMINATOR: &str = "\x1b\\";

/// URI scheme that maps to the operating system's default application for a path.
const FILE_SCHEME: &str = "file";

/// Minimum VTE version that implements OSC 8 hyperlinks (VTE 0.50).
const MINIMUM_VTE_VERSION: u32 = 5000;

/// Terminal emulators reported through `TERM_PROGRAM` that implement OSC 8 hyperlinks.
const HYPERLINK_TERMINAL_PROGRAMS: &[&str] = &[
    "ghostty",
    "hyper",
    "iterm.app",
    "mintty",
    "rio",
    "tabby",
    "vscode",
    "warpterminal",
    "wezterm",
];

/// Wraps printed text in OSC 8 hyperlinks pointing at file system paths.
#[derive(Debug, Clone)]
pub struct Hyperlinker {
    /// Whether hyperlink sequences should be emitted.
    enabled: bool,

    /// URI scheme used for generated links.
    scheme: String,
}

/// Environment variables used to detect OSC 8 hyperlink support.
#[derive(Debug, Default, Clone)]
pub struct TerminalEnvironment {
    /// Value of `TERM_PROGRAM` (set by iTerm2, Warp, `WezTerm`, mintty, and others).
    pub term_program: Option<String>,

    /// Value of `TERM` (used to detect kitty).
    pub term: Option<String>,

    /// Whether `WT_SESSION` is set, which identifies Windows Terminal.
    pub windows_terminal: bool,

    /// Whether `KONSOLE_VERSION` or `DOMTERM` is set.
    pub konsole_or_domterm: bool,

    /// Value of `VTE_VERSION` for GTK based terminals such as GNOME Terminal.
    pub vte_version: Option<String>,
}

impl Hyperlinker {
    /// Wrap `text` in an OSC 8 hyperlink that points at `path`.
    ///
    /// Returns `text` unchanged when hyperlinks are disabled or the path is empty,
    /// so callers can print the result directly in either case.
    /// The text may already contain ANSI color codes; they are preserved inside the link.
    #[must_use]
    pub fn wrap<'a>(&self, path: &str, text: &'a str) -> Cow<'a, str> {
        if !self.enabled || path.is_empty() {
            return Cow::Borrowed(text);
        }

        let uri = self.build_uri(path);
        Cow::Owned(format!(
            "{HYPERLINK_START}{uri}{HYPERLINK_TERMINATOR}{text}{HYPERLINK_START}{HYPERLINK_TERMINATOR}"
        ))
    }

    /// Whether this hyperlinker emits hyperlink sequences.
    ///
    /// Only used by unit tests that verify the configured mode.
    #[cfg(test)]
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Build the URI for a file system path.
    ///
    /// Windows separators are converted to forward slashes and unsafe characters are
    /// percent-encoded. UNC paths become `file://server/share/...`, drive paths become
    /// `file:///C:/...`, and Unix paths become `file:///path/...`.
    fn build_uri(&self, path: &str) -> String {
        let encoded = encode_uri_path(&path.replace('\\', "/"));
        let scheme = &self.scheme;

        match encoded.strip_prefix("//") {
            // UNC path: the host follows the authority marker directly
            Some(unc_path) => format!("{scheme}://{unc_path}"),
            // Unix path: already starts with the root slash
            None if encoded.starts_with('/') => format!("{scheme}://{encoded}"),
            // Drive path: needs the empty authority plus a root slash
            None => format!("{scheme}:///{encoded}"),
        }
    }

    /// Create a hyperlinker for the given mode and URI scheme.
    ///
    /// In [`HyperlinkMode::Auto`] mode, links are only emitted when standard output is a
    /// terminal that is known to support OSC 8 hyperlinks. An empty scheme falls back to `file`.
    #[must_use]
    pub fn new(mode: HyperlinkMode, scheme: &str) -> Self {
        let enabled = match mode {
            HyperlinkMode::Always => true,
            HyperlinkMode::Never => false,
            HyperlinkMode::Auto => {
                std::io::stdout().is_terminal() && TerminalEnvironment::from_env().supports_hyperlinks()
            }
        };

        let scheme = if scheme.trim().is_empty() {
            FILE_SCHEME.to_string()
        } else {
            scheme.trim().to_lowercase()
        };

        Self { enabled, scheme }
    }

    /// Create a hyperlinker that never emits hyperlink sequences.
    ///
    /// Only used by unit tests that assert on plain, unlinked output.
    #[cfg(test)]
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            enabled: false,
            scheme: String::new(),
        }
    }
}

impl TerminalEnvironment {
    /// Whether the described terminal is known to render OSC 8 hyperlinks.
    #[must_use]
    pub fn supports_hyperlinks(&self) -> bool {
        if self.windows_terminal || self.konsole_or_domterm {
            return true;
        }

        if let Some(term_program) = &self.term_program {
            let term_program = term_program.to_lowercase();
            if HYPERLINK_TERMINAL_PROGRAMS.contains(&term_program.as_str()) {
                return true;
            }
        }

        if self.term.as_ref().is_some_and(|term| term.contains("kitty")) {
            return true;
        }

        self.vte_version
            .as_ref()
            .and_then(|version| version.parse::<u32>().ok())
            .is_some_and(|version| version >= MINIMUM_VTE_VERSION)
    }

    /// Read the relevant environment variables of the current process.
    #[must_use]
    pub fn from_env() -> Self {
        Self {
            term_program: env::var("TERM_PROGRAM").ok(),
            term: env::var("TERM").ok(),
            windows_terminal: env::var_os("WT_SESSION").is_some(),
            konsole_or_domterm: env::var_os("KONSOLE_VERSION").is_some() || env::var_os("DOMTERM").is_some(),
            vte_version: env::var("VTE_VERSION").ok(),
        }
    }
}

/// Percent-encode a URI path, keeping path separators and drive colons intact.
fn encode_uri_path(path: &str) -> String {
    let mut encoded = String::with_capacity(path.len());

    for byte in path.bytes() {
        if is_uri_path_safe(byte) {
            encoded.push(byte as char);
        } else {
            let _ = write!(encoded, "%{byte:02X}");
        }
    }

    encoded
}

/// Whether a byte can appear unencoded in a URI path segment.
const fn is_uri_path_safe(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'.' | b'_' | b'~' | b'/' | b':' | b'@' | b'!' | b'$' | b'&'
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a hyperlinker that always emits links with the given scheme.
    fn linker(scheme: &str) -> Hyperlinker {
        Hyperlinker::new(HyperlinkMode::Always, scheme)
    }

    // ── URI building ──────────────────────────────────────────────

    #[test]
    fn test_build_uri_windows_drive_path() {
        assert_eq!(
            linker("file").build_uri("C:\\Videos\\movie.mp4"),
            "file:///C:/Videos/movie.mp4"
        );
    }

    #[test]
    fn test_build_uri_encodes_spaces() {
        assert_eq!(
            linker("file").build_uri("C:\\My Videos\\the movie.mp4"),
            "file:///C:/My%20Videos/the%20movie.mp4"
        );
    }

    #[test]
    fn test_build_uri_encodes_special_characters() {
        assert_eq!(
            linker("file").build_uri("C:\\a#b?c%d\\e.mp4"),
            "file:///C:/a%23b%3Fc%25d/e.mp4"
        );
    }

    #[test]
    fn test_build_uri_encodes_non_ascii_as_utf8() {
        assert_eq!(linker("file").build_uri("C:\\å.mp4"), "file:///C:/%C3%A5.mp4");
    }

    #[test]
    fn test_build_uri_unc_path() {
        assert_eq!(
            linker("file").build_uri("\\\\nas\\media\\movie.mp4"),
            "file://nas/media/movie.mp4"
        );
    }

    #[test]
    fn test_build_uri_unix_path() {
        assert_eq!(
            linker("file").build_uri("/home/me/movie.mp4"),
            "file:///home/me/movie.mp4"
        );
    }

    #[test]
    fn test_build_uri_custom_scheme() {
        assert_eq!(
            linker("vlc").build_uri("C:\\Videos\\movie.mp4"),
            "vlc:///C:/Videos/movie.mp4"
        );
    }

    #[test]
    fn test_new_empty_scheme_falls_back_to_file() {
        assert_eq!(linker("  ").build_uri("/movie.mp4"), "file:///movie.mp4");
    }

    #[test]
    fn test_new_scheme_is_lowercased() {
        assert_eq!(linker("VLC").build_uri("/movie.mp4"), "vlc:///movie.mp4");
    }

    // ── Wrapping ──────────────────────────────────────────────────

    #[test]
    fn test_wrap_emits_osc8_sequence() {
        let wrapped = linker("file").wrap("/movies/a.mp4", "a.mp4");

        assert_eq!(wrapped, "\x1b]8;;file:///movies/a.mp4\x1b\\a.mp4\x1b]8;;\x1b\\");
    }

    #[test]
    fn test_wrap_preserves_ansi_colored_text() {
        let wrapped = linker("file").wrap("/movies/a.mp4", "\x1b[32ma.mp4\x1b[0m");

        assert!(wrapped.contains("\x1b[32ma.mp4\x1b[0m"));
    }

    #[test]
    fn test_wrap_disabled_returns_borrowed_text() {
        let wrapped = Hyperlinker::disabled().wrap("/movies/a.mp4", "a.mp4");

        assert!(matches!(wrapped, Cow::Borrowed(_)));
        assert_eq!(wrapped, "a.mp4");
    }

    #[test]
    fn test_wrap_never_mode_returns_borrowed_text() {
        let wrapped = Hyperlinker::new(HyperlinkMode::Never, "file").wrap("/movies/a.mp4", "a.mp4");

        assert!(matches!(wrapped, Cow::Borrowed(_)));
    }

    #[test]
    fn test_wrap_empty_path_returns_borrowed_text() {
        let wrapped = linker("file").wrap("", "a.mp4");

        assert!(matches!(wrapped, Cow::Borrowed(_)));
    }

    #[test]
    fn test_is_enabled_reflects_mode() {
        assert!(linker("file").is_enabled());
        assert!(!Hyperlinker::new(HyperlinkMode::Never, "file").is_enabled());
        assert!(!Hyperlinker::disabled().is_enabled());
    }

    // ── Terminal detection ────────────────────────────────────────

    #[test]
    fn test_supports_hyperlinks_windows_terminal() {
        let environment = TerminalEnvironment {
            windows_terminal: true,
            ..TerminalEnvironment::default()
        };

        assert!(environment.supports_hyperlinks());
    }

    #[test]
    fn test_supports_hyperlinks_known_term_programs() {
        for program in ["iTerm.app", "WarpTerminal", "WezTerm", "mintty", "vscode", "ghostty"] {
            let environment = TerminalEnvironment {
                term_program: Some(program.to_string()),
                ..TerminalEnvironment::default()
            };

            assert!(environment.supports_hyperlinks(), "expected support for {program}");
        }
    }

    #[test]
    fn test_supports_hyperlinks_apple_terminal_is_unsupported() {
        let environment = TerminalEnvironment {
            term_program: Some("Apple_Terminal".to_string()),
            ..TerminalEnvironment::default()
        };

        assert!(!environment.supports_hyperlinks());
    }

    #[test]
    fn test_supports_hyperlinks_kitty_via_term() {
        let environment = TerminalEnvironment {
            term: Some("xterm-kitty".to_string()),
            ..TerminalEnvironment::default()
        };

        assert!(environment.supports_hyperlinks());
    }

    #[test]
    fn test_supports_hyperlinks_vte_version_threshold() {
        let supported = TerminalEnvironment {
            vte_version: Some("5202".to_string()),
            ..TerminalEnvironment::default()
        };
        let unsupported = TerminalEnvironment {
            vte_version: Some("4600".to_string()),
            ..TerminalEnvironment::default()
        };

        assert!(supported.supports_hyperlinks());
        assert!(!unsupported.supports_hyperlinks());
    }

    #[test]
    fn test_supports_hyperlinks_invalid_vte_version() {
        let environment = TerminalEnvironment {
            vte_version: Some("not-a-number".to_string()),
            ..TerminalEnvironment::default()
        };

        assert!(!environment.supports_hyperlinks());
    }

    #[test]
    fn test_supports_hyperlinks_empty_environment() {
        assert!(!TerminalEnvironment::default().supports_hyperlinks());
    }

    #[test]
    fn test_from_env_does_not_panic() {
        let _environment = TerminalEnvironment::from_env();
    }
}

//! Shell completion generation and platform-specific installation directories.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Command;
use clap_complete::Shell;

/// Generate a shell completion script for the given shell.
///
/// When `install` is `true`, the completion file is written to the appropriate shell-specific directory.
/// When `false`, the completion script is printed to stdout.
///
/// # Examples
///
/// ```no_run
/// use clap::Command;
/// use clap_complete::Shell;
/// use filefind::generate_shell_completion;
///
/// let command = Command::new("myapp").about("example app");
/// // Print the Bash completion script to stdout
/// generate_shell_completion(Shell::Bash, command, false, false, "myapp").expect("generation failed");
/// ```
///
/// # Errors
/// Returns an error if:
/// - The shell completion directory cannot be determined or created
/// - The completion file cannot be generated or written
pub fn generate_shell_completion(
    shell: Shell,
    mut command: Command,
    install: bool,
    verbose: bool,
    command_name: &str,
) -> Result<()> {
    if install {
        let out_dir = get_shell_completion_dir(shell, command_name)?;
        let path = clap_complete::generate_to(shell, &mut command, command_name, out_dir)?;
        if verbose {
            println!("Completion file generated to: {}", path.display());
        }
    } else {
        clap_complete::generate(shell, &mut command, command_name, &mut std::io::stdout());
    }
    Ok(())
}

/// Determine the appropriate directory for storing shell completions.
///
/// First checks if the user-specific directory exists,
/// then checks for the global directory.
/// If neither exist, creates and uses the user-specific dir.
fn get_shell_completion_dir(shell: Shell, name: &str) -> Result<PathBuf> {
    let home = dirs::home_dir().context("Failed to get home directory")?;

    // Special handling for oh-my-zsh.
    // Create custom "plugin", which will then have to be loaded in .zshrc
    if shell == Shell::Zsh {
        let omz_plugins = home.join(".oh-my-zsh/custom/plugins");
        if omz_plugins.exists() {
            let plugin_dir = omz_plugins.join(name);
            std::fs::create_dir_all(&plugin_dir)?;
            return Ok(plugin_dir);
        }
    }

    let user_dir = match shell {
        Shell::PowerShell => {
            if cfg!(windows) {
                home.join(r"Documents\PowerShell\completions")
            } else {
                home.join(".config/powershell/completions")
            }
        }
        Shell::Bash => home.join(".bash_completion.d"),
        Shell::Elvish => home.join(".elvish/lib"),
        Shell::Fish => home.join(".config/fish/completions"),
        Shell::Zsh => home.join(".zsh/completions"),
        _ => anyhow::bail!("Unsupported shell"),
    };

    if user_dir.exists() {
        return Ok(user_dir);
    }

    // PowerShell has no separate global directory. Skip the global fallback for it.
    let global_dir = match shell {
        Shell::Bash => Some(PathBuf::from("/etc/bash_completion.d")),
        Shell::Fish => Some(PathBuf::from("/usr/share/fish/completions")),
        Shell::Zsh => Some(PathBuf::from("/usr/share/zsh/site-functions")),
        _ => None,
    };

    if let Some(global) = global_dir
        && global.exists()
    {
        return Ok(global);
    }

    std::fs::create_dir_all(&user_dir)?;
    Ok(user_dir)
}

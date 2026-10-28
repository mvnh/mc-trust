use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

pub type Res<T> = Result<T, Box<dyn std::error::Error>>;

/// Scratch directory for *public* certificates handed to system tools.
/// Private keys never touch the disk.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new() -> Res<TempDir> {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "mc-trust-{}-{nanos}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir)?;
        Ok(TempDir(dir))
    }

    pub fn write(&self, name: &str, data: &[u8]) -> Res<String> {
        let path = self.0.join(name);
        std::fs::write(&path, data)?;
        Ok(path_str(&path)?.to_string())
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn path_str(p: &Path) -> Res<&str> {
    p.to_str().ok_or_else(|| format!("путь не в UTF-8: {}", p.display()).into())
}

/// Runs a command with the terminal attached (password prompts, sudo).
pub fn run_interactive(program: &str, args: &[&str]) -> Res<()> {
    let status = Command::new(program).args(args).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{program} {} завершился с кодом {:?}", args.join(" "), status.code()).into())
    }
}

/// Runs a command and captures its output; fails with its stderr.
pub fn run_quiet(program: &str, args: &[&str]) -> Res<String> {
    let out = Command::new(program).args(args).stdin(Stdio::null()).output()?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(format!(
            "{program} {}: {}",
            args.first().copied().unwrap_or(""),
            String::from_utf8_lossy(&out.stderr).trim()
        )
        .into())
    }
}

pub fn confirm(question: &str) -> Res<bool> {
    print!("{question} [y/N] ");
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    Ok(matches!(line.trim().to_lowercase().as_str(), "y" | "yes" | "д" | "да"))
}

pub fn sha1_upper(der: &[u8]) -> String {
    mc_trust_core::hash::hex(&mc_trust_core::hash::sha1(der)).to_uppercase()
}

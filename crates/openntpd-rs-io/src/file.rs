//! File I/O — drift file read/write, configuration file loading.
//!
//! Corresponds to OpenNTPD's drift file management in `ntpd.c` and
//! configuration file loading in `parse.y`.

use std::fs;
use std::io::{Read, Write};
use std::path::Path;

/// Error type for file operations.
#[derive(Debug)]
pub enum FileError {
    /// Underlying I/O error.
    Io(std::io::Error),
    /// Parse error in file content.
    Parse(String),
}

impl std::fmt::Display for FileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "file I/O: {e}"),
            Self::Parse(s) => write!(f, "parse error: {s}"),
        }
    }
}

impl std::error::Error for FileError {}

/// Result for file operations.
pub type FileResult<T> = Result<T, FileError>;

/// Read the drift file, returning the frequency as a double (ppm?).
///
/// The drift file format from OpenNTPD is a single floating-point
/// value with an optional sign, e.g.:
/// ```text
/// -10.500
/// ```
/// This represents the frequency offset in ppm (or the kernel `timex.freq`
/// value, depending on the version).
pub fn read_drift_file(path: &Path) -> FileResult<f64> {
    let mut contents = String::new();
    fs::File::open(path)
        .map_err(FileError::Io)?
        .read_to_string(&mut contents)
        .map_err(FileError::Io)?;
    let trimmed = contents.trim();
    trimmed
        .parse::<f64>()
        .map_err(|e| FileError::Parse(format!("drift value: {e}")))
}

/// Write the drift file atomically (temp + rename).
///
/// This avoids partial writes on crash.
pub fn write_drift_file(path: &Path, value: f64) -> FileResult<()> {
    let contents = format!("{value:.6}\n");
    let tmp_path = path.with_extension("tmp");
    {
        let mut tmp = fs::File::create(&tmp_path).map_err(FileError::Io)?;
        tmp.write_all(contents.as_bytes())
            .map_err(FileError::Io)?;
        tmp.sync_all().map_err(FileError::Io)?;
    }
    fs::rename(&tmp_path, path).map_err(FileError::Io)?;
    Ok(())
}

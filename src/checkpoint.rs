use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use tracing::info;

/// Manages reading and writing transfer position offsets for resumable
/// file processing.
///
/// The offset is persisted as a decimal string in a plain text file,
/// maintaining backward compatibility with the existing format.
pub struct Checkpoint {
    path: PathBuf,
}

impl Checkpoint {
    /// Creates a new checkpoint backed by the given file path.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Builds the checkpoint file path from an input name and suffix.
    ///
    /// The resulting path is `"{input}_{suffix}"`, matching the convention
    /// used by the existing offset files.
    #[must_use]
    pub fn from_input_and_suffix(input: &str, suffix: &str) -> Self {
        Self {
            path: PathBuf::from(format!("{input}_{suffix}")),
        }
    }

    /// Loads the stored offset, returning 0 if the file does not exist or
    /// cannot be parsed.
    #[must_use]
    pub fn load(&self) -> u64 {
        self.try_load().unwrap_or(0)
    }

    /// Returns the checkpoint file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Saves the given offset to the checkpoint file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be created or written.
    pub fn save(&self, offset: u64) -> Result<()> {
        let mut f = File::create(&self.path)
            .with_context(|| format!("cannot create {}", self.path.display()))?;
        f.write_all(offset.to_string().as_bytes())
            .with_context(|| format!("cannot write to {}", self.path.display()))?;
        Ok(())
    }

    fn try_load(&self) -> Option<u64> {
        let mut f = File::open(&self.path).ok()?;
        let mut content = String::new();
        f.read_to_string(&mut content).ok()?;
        let offset: u64 = content.parse().ok()?;
        info!("Found offset file, skipping {offset} entries");
        Some(offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_returns_zero_when_file_missing() {
        let dir = tempfile::tempdir().expect("temp dir");
        let cp = Checkpoint::new(dir.path().join("nonexistent"));
        assert_eq!(cp.load(), 0);
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempfile::tempdir().expect("temp dir");
        let cp = Checkpoint::new(dir.path().join("offset"));
        cp.save(42).expect("save");
        assert_eq!(cp.load(), 42);
    }

    #[test]
    fn load_returns_zero_for_non_numeric_content() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("bad");
        std::fs::write(&path, "not_a_number").expect("write");
        let cp = Checkpoint::new(path);
        assert_eq!(cp.load(), 0);
    }

    #[test]
    fn save_overwrites_previous_value() {
        let dir = tempfile::tempdir().expect("temp dir");
        let cp = Checkpoint::new(dir.path().join("offset"));
        cp.save(100).expect("save first");
        cp.save(200).expect("save second");
        assert_eq!(cp.load(), 200);
    }

    #[test]
    fn from_input_and_suffix_builds_correct_path() {
        let cp = Checkpoint::from_input_and_suffix("/data/conn.log", "offset");
        assert_eq!(cp.path(), Path::new("/data/conn.log_offset"));
    }
}

use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CheckpointError {
    #[error("cannot open {path}")]
    Open {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("cannot read from {path}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("cannot create {path}")]
    Create {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("cannot write to {path}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Manages reading and writing transfer positions for resumable processing.
///
/// Positions are stored as raw bytes so callers can preserve collector-
/// specific formats without forcing a numeric representation.
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
    /// The resulting path is `"{input}_{suffix}"`, matching the legacy
    /// convention used by the existing offset files.
    #[must_use]
    pub fn from_input_and_suffix(input: &str, suffix: &str) -> Self {
        Self {
            path: PathBuf::from(format!("{input}_{suffix}")),
        }
    }

    /// Loads the stored position bytes.
    ///
    /// Returns `Ok(None)` when the checkpoint file does not exist.
    ///
    /// # Errors
    ///
    /// Returns an error if opening or reading an existing checkpoint fails.
    pub fn load(&self) -> std::result::Result<Option<Vec<u8>>, CheckpointError> {
        let mut file = match File::open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(CheckpointError::Open {
                    path: self.path.clone(),
                    source,
                });
            }
        };

        let mut content = Vec::new();
        file.read_to_end(&mut content)
            .map_err(|source| CheckpointError::Read {
                path: self.path.clone(),
                source,
            })?;
        Ok(Some(content))
    }

    /// Returns the checkpoint file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Saves the given position bytes to the checkpoint file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be created or written.
    pub fn save(&self, position: &[u8]) -> std::result::Result<(), CheckpointError> {
        let mut file = File::create(&self.path).map_err(|source| CheckpointError::Create {
            path: self.path.clone(),
            source,
        })?;
        file.write_all(position)
            .map_err(|source| CheckpointError::Write {
                path: self.path.clone(),
                source,
            })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_returns_none_when_file_missing() {
        let dir = tempfile::tempdir().expect("temporary directory should be created");
        let checkpoint = Checkpoint::new(dir.path().join("nonexistent"));
        assert_eq!(
            checkpoint.load().expect("missing file is not an error"),
            None
        );
    }

    #[test]
    fn save_and_load_roundtrip_bytes() {
        let dir = tempfile::tempdir().expect("temporary directory should be created");
        let checkpoint = Checkpoint::new(dir.path().join("offset"));
        checkpoint
            .save(b"42")
            .expect("checkpoint bytes should be written");
        assert_eq!(
            checkpoint.load().expect("saved bytes should be readable"),
            Some(b"42".to_vec())
        );
    }

    #[test]
    fn save_overwrites_previous_value() {
        let dir = tempfile::tempdir().expect("temporary directory should be created");
        let checkpoint = Checkpoint::new(dir.path().join("offset"));
        checkpoint
            .save(b"100")
            .expect("first checkpoint bytes should be written");
        checkpoint
            .save(b"200")
            .expect("second checkpoint bytes should overwrite the first");
        assert_eq!(
            checkpoint.load().expect("saved bytes should be readable"),
            Some(b"200".to_vec())
        );
    }

    #[test]
    fn from_input_and_suffix_builds_correct_path() {
        let checkpoint = Checkpoint::from_input_and_suffix("/data/conn.log", "offset");
        assert_eq!(checkpoint.path(), Path::new("/data/conn.log_offset"));
    }
}

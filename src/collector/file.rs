use std::path::PathBuf;

use walkdir::WalkDir;

/// Returns all files beneath a directory, optionally filtered by prefix.
#[must_use]
pub fn files_in_dir(path: &str, prefix: Option<&str>, skip: &[PathBuf]) -> Vec<PathBuf> {
    WalkDir::new(path)
        .follow_links(true)
        .into_iter()
        .filter_map(|entry| {
            if let Ok(entry) = entry {
                if !entry.file_type().is_file() {
                    return None;
                }
                if let Some(prefix) = prefix
                    && let Some(name) = entry.path().file_name()
                    && !name.to_string_lossy().starts_with(prefix)
                {
                    return None;
                }

                let entry = entry.into_path();
                if skip.contains(&entry) {
                    None
                } else {
                    Some(entry)
                }
            } else {
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::os::unix::fs::symlink;

    use tempfile::tempdir;

    use super::files_in_dir;

    #[test]
    fn files_in_dir_returns_all_files() {
        let temp_dir = tempdir().expect("temporary directory should be created");
        let dir_path = temp_dir.path();

        File::create(dir_path.join("a.csv")).expect("test file should be created");
        File::create(dir_path.join("b.csv")).expect("test file should be created");
        File::create(dir_path.join("c.txt")).expect("test file should be created");

        let result = files_in_dir(&dir_path.to_string_lossy(), None, &[]);

        assert_eq!(result.len(), 3);
        assert!(result.contains(&dir_path.join("a.csv")));
        assert!(result.contains(&dir_path.join("b.csv")));
        assert!(result.contains(&dir_path.join("c.txt")));
    }

    #[test]
    fn files_in_dir_prefix_filtering() {
        let temp_dir = tempdir().expect("temporary directory should be created");
        let dir_path = temp_dir.path();

        File::create(dir_path.join("keep_a.csv")).expect("test file should be created");
        File::create(dir_path.join("keep_b.csv")).expect("test file should be created");
        File::create(dir_path.join("drop_a.csv")).expect("test file should be created");
        File::create(dir_path.join("other.txt")).expect("test file should be created");

        let result = files_in_dir(&dir_path.to_string_lossy(), Some("keep_"), &[]);

        assert_eq!(result.len(), 2);
        assert!(result.contains(&dir_path.join("keep_a.csv")));
        assert!(result.contains(&dir_path.join("keep_b.csv")));
        assert!(!result.contains(&dir_path.join("drop_a.csv")));
        assert!(!result.contains(&dir_path.join("other.txt")));
    }

    #[test]
    fn files_in_dir_skip_processed_files() {
        let temp_dir = tempdir().expect("temporary directory should be created");
        let dir_path = temp_dir.path();

        File::create(dir_path.join("file1.csv")).expect("test file should be created");
        File::create(dir_path.join("file2.csv")).expect("test file should be created");
        File::create(dir_path.join("file3.csv")).expect("test file should be created");

        let skip = vec![dir_path.join("file1.csv"), dir_path.join("file2.csv")];
        let result = files_in_dir(&dir_path.to_string_lossy(), None, &skip);

        assert_eq!(result.len(), 1);
        assert!(result.contains(&dir_path.join("file3.csv")));
    }

    #[test]
    fn files_in_dir_empty_directory() {
        let temp_dir = tempdir().expect("temporary directory should be created");
        let result = files_in_dir(&temp_dir.path().to_string_lossy(), None, &[]);
        assert!(result.is_empty());
    }

    #[test]
    fn files_in_dir_prefix_matches_nothing() {
        let temp_dir = tempdir().expect("temporary directory should be created");
        let dir_path = temp_dir.path();

        File::create(dir_path.join("a.csv")).expect("test file should be created");
        File::create(dir_path.join("b.csv")).expect("test file should be created");

        let result = files_in_dir(&dir_path.to_string_lossy(), Some("nonexistent_"), &[]);
        assert!(result.is_empty());
    }

    #[test]
    fn files_in_dir_excludes_directories() {
        let temp_dir = tempdir().expect("temporary directory should be created");
        let dir_path = temp_dir.path();

        File::create(dir_path.join("file.csv")).expect("test file should be created");
        std::fs::create_dir(dir_path.join("subdir")).expect("subdirectory should be created");

        let result = files_in_dir(&dir_path.to_string_lossy(), None, &[]);

        assert_eq!(result.len(), 1);
        assert!(result.contains(&dir_path.join("file.csv")));
    }

    #[test]
    fn files_in_dir_with_nested_files() {
        let temp_dir = tempdir().expect("temporary directory should be created");
        let dir_path = temp_dir.path();

        File::create(dir_path.join("root.csv")).expect("test file should be created");
        let subdir = dir_path.join("subdir");
        std::fs::create_dir(&subdir).expect("subdirectory should be created");
        File::create(subdir.join("nested.csv")).expect("nested test file should be created");

        let result = files_in_dir(&dir_path.to_string_lossy(), None, &[]);

        assert_eq!(result.len(), 2);
        assert!(result.contains(&dir_path.join("root.csv")));
        assert!(result.contains(&subdir.join("nested.csv")));
    }

    #[test]
    fn files_in_dir_prefix_filtering_with_skip() {
        let temp_dir = tempdir().expect("temporary directory should be created");
        let dir_path = temp_dir.path();

        File::create(dir_path.join("keep_a.csv")).expect("test file should be created");
        File::create(dir_path.join("keep_b.csv")).expect("test file should be created");
        File::create(dir_path.join("keep_c.csv")).expect("test file should be created");
        File::create(dir_path.join("drop_a.csv")).expect("test file should be created");

        let skip = vec![dir_path.join("keep_a.csv")];
        let result = files_in_dir(&dir_path.to_string_lossy(), Some("keep_"), &skip);

        assert_eq!(result.len(), 2);
        assert!(result.contains(&dir_path.join("keep_b.csv")));
        assert!(result.contains(&dir_path.join("keep_c.csv")));
        assert!(!result.contains(&dir_path.join("keep_a.csv")));
    }

    #[test]
    fn files_in_dir_ignores_broken_symlinks() {
        let temp_dir = tempdir().expect("temporary directory should be created");
        let dir_path = temp_dir.path();
        let broken_link = dir_path.join("broken.log");

        symlink(dir_path.join("missing.log"), &broken_link)
            .expect("broken symlink fixture should be created");

        let result = files_in_dir(&dir_path.to_string_lossy(), None, &[]);
        assert!(result.is_empty());
    }
}

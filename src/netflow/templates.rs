use std::{collections::HashMap, io::Write, net::IpAddr};

use anyhow::{Context, Result};
use num_enum::FromPrimitive;
use serde::{Deserialize, Serialize};
use tracing::info;

use super::{
    fields::{FieldTypes, OptionsScopeFieldTypes},
    packet::Netflow9Header,
};

#[allow(clippy::struct_field_names)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Template {
    pub(super) header: Netflow9Header,
    pub(super) template_id: u16,
    pub(super) field_count: u16,
    pub(super) flow_length: u64,
    pub(super) fields: Vec<(u16, u16)>,
    pub(super) options_template: bool,
    pub(super) scope_field_count: usize,
}

impl std::fmt::Display for Template {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.header)?;
        writeln!(f, "Template id: {}", self.template_id,)?;
        writeln!(f, "Field count: {}", self.field_count)?;
        writeln!(f, "Flow length: {}", self.flow_length)?;
        writeln!(f, "Options template: {}", self.options_template)?;

        if self.options_template {
            writeln!(f, "Scope fields count: {}", self.scope_field_count,)?;
            writeln!(
                f,
                "Options fields count: {}",
                self.fields.len() - self.scope_field_count
            )?;
        }

        if self.options_template {
            if self.scope_field_count > 0
                && let Some(fields) = self.fields.get(..self.scope_field_count)
            {
                writeln!(f, "Scope fields:")?;
                for (k, v) in fields {
                    writeln!(
                        f,
                        " ({:?}({k}), {v})",
                        OptionsScopeFieldTypes::from_primitive(*k)
                    )?;
                }
            }

            if let Some(fields) = self.fields.get(self.scope_field_count..) {
                writeln!(f, "Option fields:")?;
                for (k, v) in fields {
                    writeln!(
                        f,
                        " (\"Option Field {:?}({k})\", {v})",
                        FieldTypes::from_primitive(*k)
                    )?;
                }
            }
        } else {
            writeln!(f, "Fields:",)?;
            for (k, v) in &self.fields {
                writeln!(f, " (\"{:?}\", {v})", FieldTypes::from_primitive(*k))?;
            }
        }

        Ok(())
    }
}

type TemplateKey = (IpAddr, u32, u16);

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
#[allow(clippy::module_name_repetitions)]
pub(crate) struct TemplatesBox {
    templates: HashMap<TemplateKey, Template>,
}

impl TemplatesBox {
    #[must_use]
    pub(crate) fn new() -> TemplatesBox {
        TemplatesBox {
            templates: HashMap::new(),
        }
    }

    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.templates.is_empty()
    }

    #[must_use]
    pub(super) fn get(&self, key: &TemplateKey) -> Option<&Template> {
        self.templates.get(key)
    }

    #[allow(unused)]
    fn remove(&mut self, key: &TemplateKey) -> bool {
        self.templates.remove(key).is_some()
    }

    pub(super) fn add(&mut self, pkt_cnt: u64, src_addr: IpAddr, templates: &[Template]) {
        for tmpl in templates {
            let key = (src_addr, tmpl.header.source_id, tmpl.template_id);
            if self.templates.insert(key, tmpl.clone()).is_none() {
                info!(
                    "Packet #{}: New template {:?} is appended: {}",
                    pkt_cnt, key, tmpl
                );
            }
        }
    }

    /// # Errors
    ///
    /// Return error if it failed to open or read file
    /// Return error if it failed deserialize the content of file
    pub(crate) fn from_path(path: &str) -> Result<Self> {
        let bytes = std::fs::read(path)?;
        bincode::deserialize(&bytes).context("fail to read templates")
    }

    /// # Errors
    ///
    /// Return error if it failed to create file
    /// Return error if it failed to serialize the template
    pub(crate) fn save(&self, path: &str) -> Result<()> {
        let mut file = std::fs::File::create(path)?;
        let buf = bincode::serialize(self)?;
        file.write_all(&buf).context("fail to write templates")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates_present_loads_successfully() {
        // Create a temp file path
        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join("test_templates_present.bin");
        let temp_path = temp_file.to_str().expect("valid temp path");

        // Create an empty TemplatesBox, save it, and reload to verify the
        // roundtrip works when templates are present (file exists with valid
        // bincode).
        let templates = TemplatesBox::new();

        // Save templates to file
        templates.save(temp_path).expect("save should succeed");

        // Load templates from file - this exercises the "templates present" path
        let loaded = TemplatesBox::from_path(temp_path);
        assert!(
            loaded.is_ok(),
            "loading templates from existing file should succeed"
        );

        let loaded_templates = loaded.unwrap();
        // An empty TemplatesBox loaded from a valid file should still be empty
        assert!(loaded_templates.is_empty());

        // Clean up
        let _ = std::fs::remove_file(temp_path);
    }

    #[test]
    fn templates_missing_returns_io_error() {
        // Use a path that definitely does not exist
        let nonexistent_path = "/nonexistent/path/to/templates.bin";

        let result = TemplatesBox::from_path(nonexistent_path);
        assert!(result.is_err(), "loading from nonexistent path should fail");

        let err = result.unwrap_err();
        // The error should be an I/O error (file not found)
        // Check that the error message contains the expected OS error indication
        let err_string = err.to_string();
        assert!(
            err_string.contains("No such file or directory")
                || err_string.contains("cannot find the path")
                || err_string.contains("The system cannot find"),
            "error message should indicate file not found, got: {err_string}"
        );
    }

    #[test]
    fn templates_missing_empty_dir_returns_error() {
        // Create a temp directory but no template file inside
        let temp_dir = std::env::temp_dir();
        let missing_file = temp_dir.join("nonexistent_templates_file.bin");
        let missing_path = missing_file.to_str().expect("valid temp path");

        // Ensure the file does not exist
        let _ = std::fs::remove_file(missing_path);

        let result = TemplatesBox::from_path(missing_path);
        assert!(
            result.is_err(),
            "loading from missing file should return error"
        );

        let err = result.unwrap_err();
        let err_string = err.to_string();
        // The error should indicate file not found
        assert!(
            err_string.contains("No such file or directory")
                || err_string.contains("cannot find the path")
                || err_string.contains("The system cannot find"),
            "error message should indicate file not found, got: {err_string}"
        );
    }

    #[test]
    fn templates_invalid_content_returns_deserialize_error() {
        // Create a temp file with invalid (non-bincode) content
        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join("test_templates_invalid.bin");
        let temp_path = temp_file.to_str().expect("valid temp path");

        // Write invalid content (not valid bincode)
        std::fs::write(temp_path, b"invalid bincode content").expect("write should succeed");

        let result = TemplatesBox::from_path(temp_path);
        assert!(
            result.is_err(),
            "loading invalid content should return error"
        );

        let err = result.unwrap_err();
        let err_string = err.to_string();
        // The error should indicate deserialization failure
        assert!(
            err_string.contains("fail to read templates"),
            "error message should indicate deserialization failure, got: {err_string}"
        );

        // Clean up
        let _ = std::fs::remove_file(temp_path);
    }

    #[test]
    fn templates_save_and_load_roundtrip_empty() {
        // Test that an empty TemplatesBox can be saved and loaded correctly
        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join("test_templates_roundtrip_empty.bin");
        let temp_path = temp_file.to_str().expect("valid temp path");

        let templates = TemplatesBox::new();
        assert!(templates.is_empty());

        // Save and reload
        templates.save(temp_path).expect("save should succeed");
        let loaded = TemplatesBox::from_path(temp_path).expect("load should succeed");

        // Verify it's still empty after roundtrip
        assert!(loaded.is_empty());

        // Clean up
        let _ = std::fs::remove_file(temp_path);
    }

    #[test]
    fn new_templates_box_is_empty() {
        let templates = TemplatesBox::new();
        assert!(templates.is_empty());
    }

    #[test]
    fn default_templates_box_is_empty() {
        let templates = TemplatesBox::default();
        assert!(templates.is_empty());
    }
}

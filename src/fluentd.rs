use eventio::fluentd::{Entry, ForwardMode};
use serde_bytes::ByteBuf;
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SerializationError {
    #[error("too long (expected <= {})", u32::max_value())]
    TooLong,
}

const EMPTY_FORWARD_MODE_SIZE: usize = 4; // fixarray[fixstr, fixarray, nil]

pub struct SizedForwardMode {
    pub message: ForwardMode,
    size: usize,
}

impl Default for SizedForwardMode {
    fn default() -> Self {
        Self {
            message: ForwardMode {
                tag: String::default(),
                entries: Vec::default(),
                option: None,
            },
            size: EMPTY_FORWARD_MODE_SIZE,
        }
    }
}

impl SizedForwardMode {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.message.entries.len()
    }

    pub fn clear(&mut self) {
        self.message.tag.clear();
        self.message.entries.clear();
        self.message.option = None;
        self.size = EMPTY_FORWARD_MODE_SIZE;
    }

    #[must_use]
    pub fn serialized_len(&self) -> usize {
        self.size
    }

    /// # Errors
    ///
    /// Returns an error if `tag` is too long, causing a `SerializationError`.
    pub fn set_tag(&mut self, tag: String) -> Result<(), SerializationError> {
        let new_len = match msgpack_str_len(tag.len()) {
            Some(len) => len,
            None => return Err(SerializationError::TooLong),
        };
        self.size = self.size
            - msgpack_str_len(self.message.tag.len())
                .expect("tag should be shorter than 2^32 bytes")
            + new_len;
        self.message.tag = tag;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if there is no more space in `self.message` for the new
    /// entry.
    pub fn push_raw(
        &mut self,
        time: u64,
        key: &str,
        value: &[u8],
    ) -> Result<(), SerializationError> {
        if self.message.entries.len() == 15 || self.message.entries.len() == (1 << 16) - 1 {
            self.size += 2;
        } else if self.message.entries.len() == (1 << 32) - 1 {
            return Err(SerializationError::TooLong);
        }
        let serialized_key_len = match msgpack_str_len(key.len()) {
            Some(len) => len,
            None => return Err(SerializationError::TooLong),
        };
        let serialized_value_len = match msgpack_bin_len(value.len()) {
            Some(len) => len,
            None => return Err(SerializationError::TooLong),
        };
        self.size += msgpack_uint_len(time) + 2 + serialized_key_len + serialized_value_len;

        let mut record = HashMap::new();
        record.insert(key.into(), ByteBuf::from(value));
        let entry = Entry { time, record };
        self.message.entries.push(entry);
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if there is no more space in `self.message.options` for
    /// the new value.
    pub fn push_option(&mut self, key: &str, value: &str) -> Result<(), SerializationError> {
        if self.message.option.is_none() {
            self.message.option = Some(HashMap::new());
        }
        if let Some(m) = self.message.option.as_mut() {
            let serialized_value_len = match msgpack_str_len(value.len()) {
                Some(len) => len,
                None => return Err(SerializationError::TooLong),
            };
            if let Some(old_value) = m.insert(key.to_string(), value.to_string()) {
                self.size = self.size
                    - msgpack_str_len(old_value.len())
                        .expect("option should be shorter than 2^32 bytes")
                    + serialized_value_len;
            } else {
                let serialized_key_len = match msgpack_str_len(key.len()) {
                    Some(len) => len,
                    None => return Err(SerializationError::TooLong),
                };
                self.size += serialized_key_len + serialized_value_len;
                if m.len() == 16 || m.len() == 1 << 16 {
                    self.size += 2;
                } else if m.len() == 1 << 32 {
                    m.remove(key);
                    return Err(SerializationError::TooLong);
                }
            };
        }
        Ok(())
    }
}

fn msgpack_uint_len(i: u64) -> usize {
    if i < 1 << 7 {
        1
    } else if i < 1 << 8 {
        2
    } else if i < 1 << 16 {
        3
    } else if i < 1 << 32 {
        5
    } else {
        9
    }
}

fn msgpack_bin_len(len: usize) -> Option<usize> {
    if len < 1 << 8 {
        Some(2 + len)
    } else if len < 1 << 16 {
        Some(3 + len)
    } else if len < 1 << 32 {
        Some(5 + len)
    } else {
        // Too long for msgpack
        None
    }
}

fn msgpack_str_len(len: usize) -> Option<usize> {
    if len < 32 {
        Some(1 + len)
    } else {
        msgpack_bin_len(len)
    }
}

#[cfg(test)]
mod tests {
    use super::SizedForwardMode;
    use rmp_serde::Serializer;
    use serde::Serialize;

    #[test]
    fn len_empty() {
        let m = SizedForwardMode::default();
        let mut buf = Vec::new();
        m.message.serialize(&mut Serializer::new(&mut buf)).unwrap();
        assert_eq!(m.serialized_len(), buf.len());
    }

    #[test]
    fn len_tag() {
        let mut m = SizedForwardMode::default();
        m.set_tag("1234567890".to_string()).unwrap();
        let mut buf = Vec::new();
        m.message.serialize(&mut Serializer::new(&mut buf)).unwrap();
        assert_eq!(m.serialized_len(), buf.len());
    }

    #[test]
    fn len_raw() {
        let mut m = SizedForwardMode::default();
        m.push_raw(1, "raw", b"1234567890").unwrap();
        let mut buf = Vec::new();
        m.message.serialize(&mut Serializer::new(&mut buf)).unwrap();
        assert_eq!(m.serialized_len(), buf.len());

        m.push_raw(2, "raw", b"1234567890").unwrap();
        let mut buf = Vec::new();
        m.message.serialize(&mut Serializer::new(&mut buf)).unwrap();
        assert_eq!(m.serialized_len(), buf.len());
    }

    #[test]
    fn len_option() {
        let mut m = SizedForwardMode::default();
        m.push_option("test", "option").unwrap();
        let mut buf = Vec::new();
        m.message.serialize(&mut Serializer::new(&mut buf)).unwrap();
        assert_eq!(m.serialized_len(), buf.len());
    }
}

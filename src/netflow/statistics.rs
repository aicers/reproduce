use num_enum::FromPrimitive;
use std::collections::HashMap;

#[derive(Copy, Clone, Debug, PartialEq, Eq, FromPrimitive, Hash)]
#[repr(u8)]
pub enum ProcessStats {
    Packets = 0,
    Events = 1,
    V9Templates = 2,
    V5Templates = 3,
    NoNetflowPackets = 4,
    YesNetflowPackets = 5,
    NetflowV5DataPackets = 6,
    NetflowV9DataPackets = 7,
    ReservedFlowsetIDUsed = 8,
    V9OptionsTemplate = 9,
    InvalidNetflowPackets = 10,
    Unimplemented = 11,
    TemplateNotFound = 12,
    WriteFailed = 13,
    #[num_enum(default)]
    InvalidPackets = u8::MAX,
}

#[derive(Debug)]
pub struct Stats {
    stats: HashMap<ProcessStats, usize>,
}

impl Stats {
    pub fn new() -> Self {
        Self {
            stats: HashMap::new(),
        }
    }

    pub fn add(&mut self, kind: ProcessStats, cnt: usize) {
        self.stats
            .entry(kind)
            .and_modify(|c| *c += cnt)
            .or_insert_with(|| cnt);
    }
}

impl std::fmt::Display for Stats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (k, v) in &self.stats {
            writeln!(f, "  {k:?} = {v}")?;
        }
        Ok(())
    }
}

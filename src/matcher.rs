use anyhow::Result;
#[cfg(all(target_arch = "x86_64", feature = "hyperscan"))]
use hyperscan::prelude::*;
#[cfg(not(all(target_arch = "x86_64", feature = "hyperscan")))]
use regex::bytes::RegexSet;
use std::fs;

pub struct Matcher {
    #[cfg(all(target_arch = "x86_64", feature = "hyperscan"))]
    db: BlockDatabase,
    #[cfg(not(all(target_arch = "x86_64", feature = "hyperscan")))]
    db: RegexSet,
    #[cfg(all(target_arch = "x86_64", feature = "hyperscan"))]
    scratch: Scratch,
}

impl Matcher {
    #[cfg(all(target_arch = "x86_64", feature = "hyperscan"))]
    pub fn with_file(filename: &str) -> Result<Self> {
        let patterns: Patterns = fs::read_to_string(filename)?.parse()?;
        let db: BlockDatabase = patterns.build()?;
        let scratch = db.alloc_scratch()?;
        Ok(Matcher { db, scratch })
    }

    #[cfg(not(all(target_arch = "x86_64", feature = "hyperscan")))]
    pub fn with_file(filename: &str) -> Result<Self> {
        let fs = fs::read_to_string(filename)?;
        let rules = trim_to_rules(&fs);
        let db: RegexSet = RegexSet::new(rules)?;
        Ok(Matcher { db })
    }

    #[cfg(all(target_arch = "x86_64", feature = "hyperscan"))]
    pub fn scan(&mut self, data: &[u8]) -> Result<bool> {
        let mut is_matched = false;
        self.db.scan(data, &self.scratch, |_, _, _, _| {
            is_matched = true;
            Matching::Continue
        })?;
        Ok(is_matched)
    }

    #[cfg(not(all(target_arch = "x86_64", feature = "hyperscan")))]
    pub fn scan(&mut self, data: &[u8]) -> Result<bool> {
        Ok(self.db.is_match(data))
    }
}

#[cfg(not(all(target_arch = "x86_64", feature = "hyperscan")))]
fn trim_to_rules(s: &str) -> Vec<&str> {
    s.lines()
        .flat_map(|line| {
            let line = line.trim();

            if line.is_empty() || line.starts_with('#') {
                None
            } else {
                let expr = match line.find(":/") {
                    Some(off) => &line[off + 1..],
                    None => line,
                };
                Some(match (expr.starts_with('/'), expr.rfind('/')) {
                    (true, Some(end)) if end > 0 => &expr[1..end],
                    _ => expr,
                })
            }
        })
        .collect::<Vec<_>>()
}

use super::RecordType;
use serde::Deserialize;
use std::fmt::{Display, Formatter};

#[derive(Debug, Deserialize)]
pub struct Statistics {
    pub period: u16,
    pub stats: Vec<(RecordType, u64, u64)>, // protocol, packet count, packet size
}

impl Display for Statistics {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        for stat in &self.stats {
            writeln!(f, "{:?}\t{}\t{}\t{}", stat.0, stat.1, stat.2, self.period)?;
        }
        Ok(())
    }
}

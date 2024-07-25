use std::hash::Hash;
use std::{fmt::Display, hash::Hasher};

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub struct Symbol {
    pub(crate) addr: u64,
    pub(crate) name: Option<String>,
}

impl Display for Symbol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.name {
            Some(name) => write!(f, "{} (f_0x{:016X})", name, self.addr),
            None => write!(f, "Unnamed (f_0x{:016X})", self.addr),
        }
    }
}

impl Hash for Symbol {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.addr.hash(state); // only for single dso file
    }
}

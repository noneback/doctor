use anyhow::{anyhow, Error, Ok};
use procfs::process::{MMapPath, MemoryMap};

pub struct ProcessMetadata {
    proc: procfs::process::Process,
}

impl ProcessMetadata {
    pub fn new(pid: u32) -> Self {
        let proc = procfs::process::Process::new(pid as i32).unwrap();

        Self { proc: proc }
    }

    fn find_mapper(&self, addr: u64) -> Result<MemoryMap, Error> {
        if let Some(r) = self
            .proc
            .maps()?
            .0
            .iter()
            .find(|m| m.address.0 <= addr && m.address.1 > addr)
        {
            return Ok(r.clone());
        }

        Err(anyhow!("ProcessMetadata: dso not found"))
    }

    pub fn find_dso_path(&self, addr: u64) -> Result<String, Error> {
        let r = self.find_mapper(addr)?;
        {
            let path = match &r.pathname {
                procfs::process::MMapPath::Path(p) => p.to_str(),
                _ => None,
            };

            return Ok(path.unwrap_or("unknown").to_string());
        }
    }

    pub fn abs_addr(&self, v_addr: u64) -> Result<(String, u64), Error> {
        let mapper = self.find_mapper(v_addr)?;
        let path = match &mapper.pathname {
            procfs::process::MMapPath::Path(p) => p.to_str(),
            _ => None,
        }
        .ok_or(anyhow!("dso not found"))?
        .to_string();

        Ok((path, mapper.offset + (v_addr - mapper.address.0)))
    }
}

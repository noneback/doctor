use anyhow::{anyhow, Error};
use procfs::process::{MMPermissions, MemoryMap};

pub struct ProcessMetadata {
    pid: u32,
    maps: Vec<MemoryMap>,
}

impl ProcessMetadata {
    pub fn new(pid: u32) -> Result<Self, Error> {
        let proc = procfs::process::Process::new(pid as i32)?;
        let maps = proc
            .maps()?
            .0
            .into_iter()
            .filter(|m| {
                m.perms.contains(MMPermissions::READ)
                    && m.perms.contains(MMPermissions::EXECUTE)
                    && !m.perms.contains(MMPermissions::WRITE)
            })
            .collect::<Vec<_>>();

        Ok(Self { pid, maps })
    }

    pub fn find_mapper(&self, addr: u64) -> Result<&MemoryMap, Error> {
        self.maps
            .iter()
            .find(|m| m.address.0 <= addr && m.address.1 > addr)
            .ok_or(anyhow!("mapper not found"))
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

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_find_mapper() {
        let pid = 1895926;
        let proc = ProcessMetadata::new(pid).unwrap();
        let v_addr = 0x7f42b043fe43;
        for _i in 0..10 {
            println!("{:#?}", proc.abs_addr(v_addr));
        }
    }
}

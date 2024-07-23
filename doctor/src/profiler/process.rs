use std::path::PathBuf;

use anyhow::{anyhow, Error};
use procfs::process::{MMPermissions, MemoryMap};

pub struct ProcessMetadata {
    pub pid: u32,
    pub rootfs: PathBuf,
    pub cmdline: Vec<String>,
    maps: Vec<MemoryMap>,
}

impl ProcessMetadata {
    pub fn new(pid: u32) -> Result<Self, Error> {
        let proc = procfs::process::Process::new(pid as i32)?;
        let rootfs = PathBuf::from(format!("/proc/{}/root", pid));
        let cmdline = proc.cmdline()?;
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

        Ok(Self {
            pid,
            rootfs,
            cmdline,
            maps,
        })
    }

    pub fn find_mapper(&self, addr: u64) -> Result<&MemoryMap, Error> {
        self.maps
            .iter()
            .find(|m| m.address.0 <= addr && m.address.1 > addr)
            .ok_or(anyhow!("mapper not found"))
    }

    pub fn abs_addr(&self, v_addr: u64) -> Result<(PathBuf, u64), Error> {
        let mapper = self.find_mapper(v_addr)?;
        match &mapper.pathname {
            procfs::process::MMapPath::Path(p) => {
                let path = match p.to_str().unwrap().strip_suffix(" (deleted)") {
                    Some(striped) => self.rootfs.join(striped),
                    None => self.rootfs.join(p),
                };

                Ok((path, mapper.offset + (v_addr - mapper.address.0)))
            }
            _ => Err(anyhow!("dso not found")),
        }
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

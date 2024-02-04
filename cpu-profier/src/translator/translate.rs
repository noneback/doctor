use std::{
    collections::BTreeMap,
    fs::File,
    io::{self, BufRead, BufReader},
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Error};
use blazesym::{
    symbolize::{CodeInfo, Symbolizer},
    Addr,
};
use cpu_profier_common::StackInfo;
use procfs::process::{self, Process};

pub struct Translator {
    rootfs: PathBuf,
    ksyms: Option<BTreeMap<u64, String>>,
}

impl Translator {
    pub fn new(rootfs: PathBuf) -> Self {
        Self {
            rootfs: rootfs,
            ksyms: None,
        }
    }

    pub fn translate_ksyms(&mut self, kframe: &StackInfo) -> Result<String, Error> {
        let reader = BufReader::new(File::open(self.rootfs.join("/proc/kallsyms"))?);
        if self.ksyms.is_none() {
            self.ksyms = Some(BTreeMap::new());
            for line in reader.lines() {
                let text = line?;
                let parts = text.splitn(4, ' ').collect::<Vec<_>>();
                let addr = u64::from_str_radix(parts[0], 16)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, text.clone()))?;
                let name = parts[2].to_owned();
                self.ksyms.as_mut().unwrap().insert(addr, name);
            }
        }

        if let Some(ksyms) = &self.ksyms {
            return Ok(ksyms
                .range(..=kframe.kernel_stack_id.unwrap() as u64)
                .next_back()
                .map(|(_, s)| s.clone())
                .unwrap());
        }
        Err(anyhow::anyhow!("translate_ksyms ERROR"))
    }

    pub fn translate_usyms(&mut self, uframe: &StackInfo) -> Result<String, Error> {
        Err(anyhow::anyhow!("ERROR"))
    }
}

pub fn translate_usyms(uframe: &StackInfo) -> Result<String,Error> {
    // get mappings
    let p = process::Process::new(uframe.tgid as i32)?;

    let mappings=p.maps()?;

    
    

    Err(anyhow::anyhow!("translate_usyms ERROR"))
}

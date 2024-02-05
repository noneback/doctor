use std::{
    collections::BTreeMap,
    fs::File,
    io::{self, BufRead, BufReader},
    path::PathBuf,
};

use anyhow::{anyhow, Error, Ok};
use aya::maps::stack_trace::StackTrace;
use blazesym::symbolize::{Input, Process, Source, Symbolizer};
use cpu_profier_common::StackInfo;

use super::perf_record::PerfRecord;

pub struct Translator {
    rootfs: PathBuf,
    ksyms: Option<BTreeMap<u64, String>>,
    symbolizer: Symbolizer,
}

impl Translator {
    pub fn new(rootfs: PathBuf) -> Self {
        Self {
            rootfs: rootfs,
            ksyms: None,
            symbolizer: Symbolizer::new(),
        }
    }

    pub fn translate_single(stack: &StackInfo, trace: &StackTrace) -> Result<PerfRecord, Error> {
        unimplemented!("not ready")
    }

    pub fn translate_ksyms(&mut self, ip: u64) -> Result<String, Error> {
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
                .range(..=ip)
                .next_back()
                .map(|(_, s)| s.clone())
                .unwrap());
        }
        Err(anyhow::anyhow!("translate_ksyms ERROR"))
    }

    pub fn translate_usyms(&self, ustack: &StackInfo, ip: u64) -> Result<String, Error> {
        let src = Source::Process(Process::new(ustack.tgid.into()));

        let sym = self
            .symbolizer
            .symbolize_single(&src, Input::AbsAddr(ip))
            .map_err(|e| anyhow!("symbolizer -> {}", e))?;

        match sym {
            blazesym::symbolize::Symbolized::Sym(symbol) => Ok(format!("{}", symbol.name)),
            blazesym::symbolize::Symbolized::Unknown(_) => Ok(format!("unknown_{}", ip)),
        }
    }
}

use std::{
    collections::BTreeMap,
    fs::File,
    io::{self, BufRead, BufReader},
    path::PathBuf,
    sync::Arc,
};

use anyhow::{anyhow, Error, Ok};
use aya::maps::stack_trace::StackTrace;
use blazesym::symbolize::{Input, Process, Source, Symbolizer};
use cpu_profier_common::StackInfo;

use super::perf_record::PerfStackFrame;

pub struct Translator {
    rootfs: PathBuf,
    ksyms: Option<BTreeMap<u64, String>>,
    symbolizer: Arc<Symbolizer>,
}

impl Translator {
    pub fn new(rootfs: PathBuf) -> Self {
        Self {
            rootfs: rootfs,
            ksyms: None,
            symbolizer: Arc::new(Symbolizer::new()),
        }
    }

    pub fn translate_ktrace(&mut self, ktrace: &StackTrace) -> Result<Vec<PerfStackFrame>, Error> {
        // for frame in record.stack_frames {}
        let mut frames = Vec::new();
        for f in ktrace.frames() {
            frames.push(
                self.translate_ksyms(f.ip)
                    .map_err(|e| anyhow!("translate_single -> {}", e))?,
            );
        }

        Ok(frames)
    }

    pub fn translate_utrace(
        &mut self,
        pid: u32,
        utrace: &StackTrace,
    ) -> Result<Vec<PerfStackFrame>, Error> {
        // for frame in record.stack_frames {}
        let ips = utrace.frames().iter().map(|f| f.ip).collect::<Vec<_>>();
        self.translate_usyms(pid, ips)
            .map_err(|e| anyhow!("translate_utrace -> {}", e))
    }

    pub fn translate_ksyms(&mut self, ip: u64) -> Result<PerfStackFrame, Error> {
        let elf_path = self.rootfs.join("/proc/kallsyms");

        if self.ksyms.is_none() {
            let reader = BufReader::new(File::open(&elf_path)?);
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
                .map(|(_, s)| {
                    PerfStackFrame::new(
                        ip,
                        format!("{}_[k]", s),
                        elf_path.to_str().unwrap_or("unknow_kernel_elf").to_string(),
                    )
                })
                .unwrap());
        }
        Err(anyhow::anyhow!("translate_ksyms 0x{} NotFound", ip))
    }

    pub fn translate_usyms(&self, pid: u32, ips: Vec<u64>) -> Result<Vec<PerfStackFrame>, Error> {
        let src = Source::Process(Process::new(pid.into()));
        let syms = self
            .symbolizer
            .symbolize(&src, Input::AbsAddr(&ips))
            .map_err(|e| anyhow!("symbolizer -> {}", e))?;

        Ok(syms
            .iter()
            .zip(ips)
            .map(|(sym, ip)| match sym {
                blazesym::symbolize::Symbolized::Sym(symbol) => PerfStackFrame::new(
                    ip,
                    format!("{}_[u]", symbol.name),
                    if symbol.code_info.is_none() {
                        "unknown".to_string()
                    } else {
                        match &symbol.code_info {
                            Some(code_info) => {
                                if let Some(path) = code_info.to_path().to_str() {
                                    path.to_string()
                                } else {
                                    "unknown".to_string()
                                }
                            }
                            None => "unkonwn".to_string(),
                        }
                    },
                ),
                blazesym::symbolize::Symbolized::Unknown(reason) => {
                    PerfStackFrame::new(ip, format!("unknown_0x{:x}_[u]", ip), reason.to_string())
                }
            })
            .collect())
    }
}

use std::{
    collections::BTreeMap,
    fs::File,
    io::{self, BufRead, BufReader},
    path::PathBuf,
    sync::Arc,
};

use anyhow::{anyhow, Error};
use aya::maps::stack_trace::StackTrace;

use super::{
    error::TranslateError, perf_record::PerfStackFrame, process::ProcessMetadata,
    symbolizer::symbolizer::Symbolizer,
};

pub struct Translator {
    rootfs: PathBuf,
    ksyms: Option<BTreeMap<u64, String>>,
    symbolizer: Arc<Symbolizer>,
}

impl Translator {
    pub fn new(rootfs: PathBuf) -> Self {
        Self {
            rootfs,
            ksyms: None,
            symbolizer: Arc::new(
                Symbolizer::new("/root/workspace/profiler/bianque/doctor/tests".into()).unwrap(),
            ), // TODO:
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
            .map_err(|e| anyhow!("translate_utrace pid {} -> {}", pid, e))
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
                .map(|(_, s)| PerfStackFrame::new(ip, format!("{}_[k]", s), elf_path, ip))
                .unwrap());
        }
        Err(anyhow::anyhow!("translate_ksyms 0x{} NotFound", ip))
    }

    pub fn translate_usyms(
        &mut self,
        pid: u32,
        ips: Vec<u64>,
    ) -> Result<Vec<PerfStackFrame>, TranslateError> {
        let proc = ProcessMetadata::new(pid)?;
        let mut frames = Vec::new();

        for ip in ips {
            if let Ok((dso_path, offset)) = proc.abs_addr(ip) {
                let psf = match self.symbolizer.symbolize(&proc.rootfs, &dso_path, offset) {
                    Ok(sym) => PerfStackFrame::new(
                        ip,
                        sym.name.unwrap_or("unknown".into()),
                        dso_path,
                        offset,
                    ),
                    Err(e) => {
                        log::debug!("Symbolize {}, file {:#?}: {}", pid, &dso_path, e);
                        PerfStackFrame::new(ip, "unknown".into(), dso_path.clone(), offset)
                    }
                };

                frames.push(psf);
            }
        }

        Ok(frames)
    }
}

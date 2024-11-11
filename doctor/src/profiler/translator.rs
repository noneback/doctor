use std::{
    collections::{BTreeMap, HashMap},
    fs::File,
    io::{self, BufRead, BufReader},
    path::PathBuf,
    sync::Arc,
};

use anyhow::{anyhow, Error};
use aya::maps::stack_trace::StackTrace;
use blazesym::symbolize::Symbolizer;

use super::{
    dso::Dso, error::TranslateError, perf_record::PerfStackFrame, process::ProcessMetadata,
    symbolizer::symbolizerr::Symbolizerr,
};

pub struct Translator {
    rootfs: PathBuf,
    ksyms: Option<BTreeMap<u64, String>>,
    symbolizer: Arc<Symbolizer>,
    dso_cache: BTreeMap<PathBuf, Dso>,
}

impl Translator {
    pub fn new(rootfs: PathBuf) -> Self {
        Self {
            rootfs,
            ksyms: None,
            symbolizer: Arc::new(Symbolizer::new()),
            dso_cache: BTreeMap::new(),
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
        self.translate_usyms_v3(pid, ips)
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

    pub fn translate_usyms_v2(
        &mut self,
        pid: u32,
        ips: Vec<u64>,
    ) -> Result<Vec<PerfStackFrame>, Error> {
        let proc = ProcessMetadata::new(pid)?;
        let mut frames = Vec::new();

        for ip in ips {
            if let Ok((dso_path, offset)) = proc.abs_addr(ip) {
                let dso = self
                    .dso_cache
                    .entry(dso_path.clone())
                    .or_insert_with(|| Dso::new(dso_path.clone()));

                let sym = dso
                    .translate_single(&self.symbolizer, offset)
                    .map_err(|e| {
                        anyhow!(
                            "translate_usyms_v2, cmdline {:?}, pid {} -> {}",
                            proc.cmdline,
                            pid,
                            e
                        )
                    })?;

                if !sym.eq("unknown") {
                    frames.push(PerfStackFrame::new(ip, sym, dso_path.clone(), offset));
                }
            }
        }

        Ok(frames)
    }

    pub fn translate_usyms_v3(
        &mut self,
        pid: u32,
        ips: Vec<u64>,
    ) -> Result<Vec<PerfStackFrame>, TranslateError> {
        let symer = Symbolizerr::new("/root/workspace/profiler/bianque/doctor/tests".into())?;
        let proc = ProcessMetadata::new(pid)?;
        let mut frames = Vec::new();

        for ip in ips {
            if let Ok((dso_path, offset)) = proc.abs_addr(ip) {
                let _dso = self
                    .dso_cache
                    .entry(dso_path.clone())
                    .or_insert_with(|| Dso::new(dso_path.clone()));

                let psf = match symer.symbolize(&dso_path, offset) {
                    Ok(sym) => PerfStackFrame::new(
                        ip,
                        sym.name.unwrap_or("unknown".into()),
                        dso_path.clone(),
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

    pub fn translate_usyms(
        &mut self,
        pid: u32,
        ips: Vec<u64>,
    ) -> Result<Vec<PerfStackFrame>, Error> {
        let proc = ProcessMetadata::new(pid)?;
        let mut dso_offsets: HashMap<PathBuf, Vec<(u64, u64)>> = HashMap::new();

        ips.iter().for_each(|&ip| {
            if let Ok((dso, offset)) = proc.abs_addr(ip) {
                dso_offsets.entry(dso).or_default().push((offset, ip));
            }
        });

        let mut frames = dso_offsets
            .iter()
            .flat_map(|(path, mapping)| {
                // use cache
                let dso = self
                    .dso_cache
                    .entry(path.clone())
                    .or_insert_with(|| Dso::new(path.clone()));

                let offsets = mapping
                    .iter()
                    .map(|&(offset, _ip)| offset)
                    .collect::<Vec<_>>();
                let ips = mapping.iter().map(|(_offset, ip)| ip).collect::<Vec<_>>();

                dso.translate(&self.symbolizer, &offsets)
                    .unwrap()
                    .into_iter()
                    .zip(ips)
                    .map(|(symbol, ip)| (ip, PerfStackFrame::new(*ip, symbol, path.clone(), 0)))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        frames.sort_by_key(|item| item.0);

        Ok(frames.into_iter().map(|f| f.1).collect())
    }
}

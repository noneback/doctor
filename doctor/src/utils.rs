use aya_log::EbpfLogger;
use clap::Parser;

use anyhow::Error;
use aya::maps::{MapData, StackTraceMap};
use aya::programs::{
    KProbe, PerfEvent, PerfEventScope, PerfTypeId, SamplePolicy, TracePoint, UProbe,
};
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Ebpf};
use doctor_common::StackInfo;
use log::{debug, warn};

use crate::profiler::perf_record::PerfRecord;
use crate::profiler::translator::Translator;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct ProfileOptions {
    #[arg(short, long)]
    pub pid: Option<u32>,
    /// Duration in sec
    #[arg(short, long, default_value = "5")]
    pub duration: u32,
    /// Frequency for sampling,
    #[arg(short, long, default_value_t = 99)]
    pub frequency: u64,
    /// Avoid profiling idle cpu cycles
    #[arg(long, default_value_t = true)]
    pub skip_idle: bool,
    /// function name to attached kprobe
    #[arg(long)]
    pub kprobe: Option<String>,
    /// function name to attached uprobe
    #[arg(long)]
    pub uprobe: Option<String>,
    /// function name to attached tracepoint eg.
    #[arg(long)]
    pub tracepoint: Option<String>,
    /// target CPU to profile
    #[arg(long)]
    pub cpu: Option<u32>,
}

pub fn load_ebpf(opts: &ProfileOptions) -> Result<Ebpf, Error> {
    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut ebpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/doctor"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/doctor"
    ))?;
    if let Err(e) = EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    // This will raise scheduled events on each CPU at 1 HZ, triggered by the kernel based
    // on clock ticks.
    if let Some(kprobe) = &opts.kprobe {
        let program: &mut KProbe = ebpf.program_mut("kprobe_profile").unwrap().try_into()?;
        program.load()?;
        program.attach(kprobe, 0)?;
    } else if let Some(uprobe) = &opts.uprobe {
        let program: &mut UProbe = ebpf.program_mut("uprobe_profile").unwrap().try_into()?;
        program.load()?;
        program.attach(Some(uprobe), 0, "libc", None)?;
    } else if let Some(tracepoint) = &opts.tracepoint {
        let program: &mut TracePoint =
            ebpf.program_mut("tracepoint_profile").unwrap().try_into()?;
        program.load()?;

        let mut split = tracepoint.split(':');
        let category = split.next().expect("category");
        let name = split.next().expect("name");

        program.attach(category, name)?;
    } else {
        let program: &mut PerfEvent = ebpf.program_mut("profile_cpu").unwrap().try_into()?;

        program.load()?;

        // https://elixir.bootlin.com/linux/v4.2/source/include/uapi/linux/perf_event.h#L103
        const PERF_COUNT_SW_CPU_CLOCK: u64 = 0;

        if let Some(pid) = opts.pid {
            program.attach(
                PerfTypeId::Software,
                PERF_COUNT_SW_CPU_CLOCK,
                PerfEventScope::OneProcessAnyCpu { pid },
                SamplePolicy::Frequency(opts.frequency),
                true,
            )?;
        } else if let Some(cpu) = opts.cpu {
            program.attach(
                PerfTypeId::Software,
                PERF_COUNT_SW_CPU_CLOCK,
                PerfEventScope::AllProcessesOneCpu { cpu },
                SamplePolicy::Frequency(opts.frequency),
                true,
            )?;
        } else {
            let cpus = online_cpus().map_err(|(_, error)| error)?;
            let nprocs = cpus.len();
            eprintln!("CPUs: {}", nprocs);

            for cpu in cpus {
                program.attach(
                    PerfTypeId::Software,
                    PERF_COUNT_SW_CPU_CLOCK,
                    PerfEventScope::AllProcessesOneCpu { cpu },
                    SamplePolicy::Frequency(opts.frequency),
                    true,
                )?;
            }
        }
    }

    Ok(ebpf)
}

pub fn deconstruct_stack(
    stack: &StackInfo,
    stack_traces: &StackTraceMap<MapData>,
    translator: &mut Translator,
) -> Result<PerfRecord, Error> {
    let mut kframes = None;
    let mut uframes = None;

    if let Some(id) = stack.kernel_stack_id {
        kframes = stack_traces
            .get(&(id as u32), 0)
            .map(|trace| translator.translate_ktrace(&trace).ok())?;
    }

    if let Some(id) = stack.user_stack_id {
        uframes = stack_traces
            .get(&(id as u32), 0)
            .map(|trace| translator.translate_utrace(stack.pid, &trace).ok())?;
    }

    Ok(PerfRecord::from(stack, kframes, uframes))
}

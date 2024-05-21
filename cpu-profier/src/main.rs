use clap::Parser;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Error;
use aya::maps::{HashMap, MapData, Queue, StackTraceMap};
use aya::programs::{perf_event, PerfEvent};
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use cpu_profier_common::StackInfo;
use log::{debug, info, warn};
use profiler::perf_record::PerfRecord;

use tokio::signal;

use crate::profiler::translate::Translator;
mod profiler;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]

struct ProfileOptions {
    #[arg(short, long)]
    pid: Option<u32>,
    #[arg(short, long, default_value = "5")]
    duration: u32,
    #[arg(short, long)]
    frequency: Option<u32>,
    #[arg(long)]
    debug: Option<bool>,
}

fn load_ebpf(opts: ProfileOptions) -> Result<Bpf, Error> {
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
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/cpu-profier"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/cpu-profier"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    // This will raise scheduled events on each CPU at 1 HZ, triggered by the kernel based
    // on clock ticks.
    let program: &mut PerfEvent = bpf.program_mut("cpu_profier").unwrap().try_into()?;
    program.load()?;

    if let Some(pid) = opts.pid {
        program.attach(
            perf_event::PerfTypeId::Software,
            perf_event::perf_sw_ids::PERF_COUNT_SW_CPU_CLOCK as u64,
            perf_event::PerfEventScope::OneProcessAnyCpu { pid },
            perf_event::SamplePolicy::Frequency(1000),
            false,
        )?;
    } else {
        // attach to all
        for cpu in online_cpus()? {
            program.attach(
                perf_event::PerfTypeId::Software,
                perf_event::perf_sw_ids::PERF_COUNT_SW_CPU_CLOCK as u64,
                perf_event::PerfEventScope::AllProcessesOneCpu { cpu }, // where put options
                perf_event::SamplePolicy::Frequency(1000),
                false,
            )?;
        }
    }
    Ok(bpf)
}
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    // read cmdline opt
    let opts = ProfileOptions::parse();

    let mut bpf = load_ebpf(opts)?;
    const STACK_INFO_SIZE: usize = std::mem::size_of::<StackInfo>();

    let mut stacks = Queue::<_, [u8; STACK_INFO_SIZE]>::try_from(bpf.take_map("STACKS").unwrap())?;
    let _stack_count =
        HashMap::<_, [u8; STACK_INFO_SIZE], u64>::try_from(bpf.take_map("counts").unwrap())
            .unwrap();
    let stack_traces = StackTraceMap::try_from(bpf.map("stack_traces").unwrap()).unwrap();

    info!("Waiting for Ctrl-C...");
    let running = Arc::new(AtomicBool::new(true));

    let running_clone = Arc::clone(&running);
    let handle = tokio::spawn(async move {
        let _ = signal::ctrl_c().await;
        running.store(false, Ordering::SeqCst);
    });

    let mut translator = Translator::new("/".into());
    while running_clone.load(Ordering::SeqCst) {
        match stacks.pop(0) {
            Ok(v) => {
                let stack: StackInfo = unsafe { *v.as_ptr().cast() };

                let record = deconstruct_stack(&stack, &stack_traces, &mut translator).unwrap();

                println!("{}", record);
            }
            _ => {
                info!("Nothing");
                tokio::time::sleep(Duration::from_millis(1000)).await;
            }
        }
    }

    info!("Exiting... ");
    handle.await?;
    Ok(())
}

fn deconstruct_stack(
    stack: &StackInfo,
    stack_traces: &StackTraceMap<&MapData>,
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

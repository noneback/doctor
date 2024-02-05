use std::time::Duration;

use anyhow::Error;
use aya::maps::{HashMap, Queue, StackTraceMap};
use aya::programs::{perf_event, PerfEvent};
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use cpu_profier_common::StackInfo;
use log::{debug, info, warn};
use tokio::signal;

use crate::profiler::formater;
use crate::profiler::translate::Translator;
mod profiler;

fn load_ebpf() -> Result<Bpf, Error> {
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
    for cpu in online_cpus()? {
        program.attach(
            perf_event::PerfTypeId::Software,
            perf_event::perf_sw_ids::PERF_COUNT_SW_CPU_CLOCK as u64,
            perf_event::PerfEventScope::AllProcessesOneCpu { cpu },
            perf_event::SamplePolicy::Frequency(100),
            false,
        )?;
    }
    Ok(bpf)
}
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    let mut bpf = load_ebpf()?;
    const STACK_INFO_SIZE: usize = std::mem::size_of::<StackInfo>();

    let mut stacks = Queue::<_, [u8; STACK_INFO_SIZE]>::try_from(bpf.take_map("STACKS").unwrap())?;
    let stack_count =
        HashMap::<_, [u8; STACK_INFO_SIZE], u64>::try_from(bpf.take_map("counts").unwrap())
            .unwrap();
    let stack_traces = StackTraceMap::try_from(bpf.map("stack_traces").unwrap()).unwrap();



    info!("Waiting for Ctrl-C...");
    let mut translator = Translator::new("/".into());

    let mut idx = 0;
    loop {
        if stacks.capacity() <= 0 || idx >= 1000 {
            break;
        }
        idx += 1;
        match stacks.pop(0) {
            Ok(v) => {
                let stack: StackInfo = unsafe { *v.as_ptr().cast() };

                let mut format_str = format!(
                    "{} cpu_{} {}",
                    stack.tgid,
                    stack.cpu,
                    String::from_utf8_lossy(&stack.cmd).trim_matches('\0')
                );

                if let Some(kid) = stack.kernel_stack_id {
                    format_str.push_str(
                        stack_traces
                            .get(&(kid as u32), 0)
                            .map(|trace| formater::format(&mut translator, &stack, &trace, true))?
                            .as_str(),
                    );
                }
                if let Some(uid) = stack.user_stack_id {
                    format_str.push_str(
                        stack_traces
                            .get(&(uid as u32), 0)
                            .map(|trace| formater::format(&mut translator, &stack, &trace, false))?
                            .as_str(),
                    );
                }
                println!("{}", format_str);
            }
            _ => {
                tokio::time::sleep(Duration::from_millis(1000)).await;
            }
        }
    }
    signal::ctrl_c().await?;
    info!("stacks : {}", stacks.capacity());

    info!("Exiting... ");

    Ok(())
}

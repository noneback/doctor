use anyhow::anyhow;
use clap::Parser;
use profiler::translator::{Translator};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Instant;
use utils::{deconstruct_stack, load_ebpf, ProfileOptions};

use aya::maps::{HashMap, RingBuf, StackTraceMap};
use doctor_common::StackInfo;
use log::info;
use tokio::{signal, task};
mod profiler;
mod utils;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    let opts = ProfileOptions::parse();
    let mut bpf = load_ebpf(&opts)?;

    let mut tlor = Translator::new("/".into());

    const STACK_INFO_SIZE: usize = std::mem::size_of::<StackInfo>();

    let stack_traces = StackTraceMap::try_from(
        bpf.take_map("stack_traces")
            .ok_or(anyhow!("stack_traces not found"))?,
    )?;

    let mut counts = HashMap::<_, [u8; STACK_INFO_SIZE], u64>::try_from(
        bpf.take_map("counts").ok_or(anyhow!("counts not found"))?,
    )?;

    let mut trace_count = std::collections::HashMap::new();
    let mut samples;
    let mut queue_processed = 0;

    let (perf_tx, perf_rx) = mpsc::channel();

    task::spawn(async move {
        let ring_buf = RingBuf::try_from(bpf.map_mut("RING_BUF_STACKS").unwrap()).unwrap();
        use tokio::io::unix::AsyncFd;
        let mut fd = AsyncFd::new(ring_buf).unwrap();

        while let Ok(mut guard) = fd.readable_mut().await {
            match guard.try_io(|inner| {
                let ring_buf = inner.get_mut();
                while let Some(item) = ring_buf.next() {
                    // println!("Received: {:?}", item);
                    let stack: StackInfo = unsafe { *item.as_ptr().cast() };
                    // println!(
                    //     "Stack {:?}, cmd: {}",
                    //     stack,
                    //     profile_bee::symbols::str_from_u8_nul_utf8(&stack.cmd).unwrap()
                    // );
                    let _ = perf_tx.send(stack);
                }
                Ok(())
            }) {
                Ok(_) => {
                    guard.clear_ready();
                    continue;
                }
                Err(_would_block) => continue,
            }
        }
    });
    let running = Arc::new(AtomicBool::new(true));

    let running_clone = Arc::clone(&running);
    let handle = tokio::spawn(async move {
        let _ = signal::ctrl_c().await;
        running.store(false, Ordering::SeqCst);
    });

    while running_clone.load(Ordering::SeqCst) {
        let started = Instant::now();
        trace_count.clear();
        samples = 0;
        // clear "counts" hashmap
        let keys = counts.keys().flatten().collect::<Vec<_>>();
        for k in keys {
            let _ = counts.remove(&k);
        }
        /* Perf mpsc RX loop */
        while let Ok(stack) = perf_rx.recv() {
            queue_processed += 1;

            // user space counting
            let trace = trace_count.entry(stack).or_insert(0);
            *trace += 1;

            if started.elapsed().as_secs() > opts.duration as _ {
                break;
            }
        }
        println!("Processed {} queue events", queue_processed);

        println!("Processing stacks...");
        for (key, value) in counts.iter().flatten() {
            let stack: StackInfo = unsafe { *key.as_ptr().cast() };
            samples += value;
            let record = deconstruct_stack(&stack, &stack_traces, &mut tlor)?;
            println!("{}", record);
        }

        println!("Total samples: {}", samples);
    }

    info!("Exiting... ");
    Ok(())
}

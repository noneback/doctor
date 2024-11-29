#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{kprobe, perf_event, tracepoint, uprobe},
    programs::{PerfEventContext, ProbeContext, TracePointContext},
};
use doctor_ebpf::collect_trace;

#[perf_event]
pub fn profile_cpu(ctx: PerfEventContext) -> u32 {
    unsafe {
        collect_trace(ctx);
    }

    0
}

#[kprobe]
pub fn kprobe_profile(ctx: ProbeContext) -> u32 {
    unsafe { collect_trace(ctx) }
    0
}

#[uprobe]
pub fn uprobe_profile(ctx: ProbeContext) -> u32 {
    unsafe { collect_trace(ctx) }
    0
}

#[tracepoint]
pub fn tracepoint_profile(ctx: TracePointContext) -> u32 {
    unsafe { collect_trace(ctx) }
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#![no_std]
#![no_main]

use core::{borrow::BorrowMut, ptr::NonNull};

use aya_bpf::{
    bindings::BPF_F_USER_STACK,
    helpers::bpf_get_smp_processor_id,
    macros::{map, perf_event},
    maps::{HashMap, Queue, StackTrace},
    programs::PerfEventContext,
    BpfContext,
};

use aya_log_ebpf::info;
use cpu_profier_common::{skip_idle, StackInfo};

const STACK_SIZE: u32 = 10000;

#[map(name = "stack_trace")]
pub static mut STACK_TRACE: StackTrace = StackTrace::with_max_entries(STACK_SIZE, 0);

#[map]
pub static STACKS: Queue<StackInfo> = Queue::with_max_entries(STACK_SIZE, 0);

#[map(name = "counts")]
pub static mut COUNTS: HashMap<StackInfo, u64> = HashMap::with_max_entries(STACK_SIZE, 0);

#[perf_event]
pub fn cpu_profier(ctx: PerfEventContext) -> u32 {
    let pid = match try_cpu_profier(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    };
    return pid;
}

#[inline(always)]
unsafe fn try_get_stack_info(ctx: &PerfEventContext) -> StackInfo {
    let (cpu, tgid, pid, cmd) = (
        bpf_get_smp_processor_id(),
        ctx.tgid(),
        ctx.pid(),
        ctx.command().unwrap_or_default(),
    );

    let (user_stack_id, kernel_stack_id) = (
        STACK_TRACE
            .get_stackid(ctx, BPF_F_USER_STACK.into())
            .ok()
            .and_then(|v| Some(v as i32)),
        STACK_TRACE
            .get_stackid(ctx, 0)
            .ok()
            .and_then(|v| Some(v as i32)),
    );

    StackInfo {
        cpu,
        tgid,
        // pid,
        cmd,
        user_stack_id,
        kernel_stack_id,
    }
}

unsafe fn try_profile(ctx: &PerfEventContext) -> Result<u32, u32> {
    if skip_idle() && ctx.pid() == 0 {
        // not profiling idle
        return Ok(0);
    }

    let stack_info = try_get_stack_info(&ctx);

    // info!(
    //     ctx,
    //     "perf event: u stack info pid {} tgid {}  stack[ u {} -> k {} ]",
    //     stack_info.pid,
    //     stack_info.tgid,
    //     stack_info.user_stack_id.unwrap_or(-1),
    //     stack_info.kernel_stack_id.unwrap_or(-1)
    // );

    match COUNTS.get_ptr_mut(&stack_info) {
        Some(cnt) => {
            *cnt += 1;
            // info!(ctx, "Found in Counts: {}", *cnt)
        }
        None => {
            COUNTS.insert(&stack_info, &1, 0);
            // info!(ctx, "Not Found in Counts, insert a new one")
        }
    }
    STACKS.push(&stack_info, 0);
    Ok(0)
}

fn try_cpu_profier(ctx: PerfEventContext) -> Result<u32, u32> {
    unsafe { try_profile(&ctx) }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

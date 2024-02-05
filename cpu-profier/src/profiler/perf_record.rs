use aya::maps::stack_trace::{StackFrame, StackTrace};
use cpu_profier_common::StackInfo;

pub struct PerfRecord {
    pid: u32,
    tgid: u32,
    cpu_id: u32,
    cmdline: String,
    ts: u64,
    cycle: u64,
    stack_frames: Vec<PerfStackFrame>,
}

pub enum StackFrameType {
    Kernel,
    User,
}

pub struct PerfStackFrame {
    ip: u64,
    sym: Option<String>,
    typ: StackFrameType,
    elf: Option<String>,
}

impl PerfStackFrame {
    pub fn new(ip: u64, typ: StackFrameType) -> Self {
        Self {
            ip: ip,
            sym: None,
            typ: typ,
            elf: None,
        }
    }

    pub fn fill_up(&self) {
        unimplemented!("ss")
    }
}

impl PerfRecord {
    pub fn from(stack: &StackInfo, trace: &StackTrace) -> Self {
        let frames: Vec<PerfStackFrame> = trace
            .frames()
            .iter()
            .map(|t| {
                PerfStackFrame::new(
                    t.ip,
                    if stack.kernel_stack_id.is_some() {
                        StackFrameType::Kernel
                    } else {
                        StackFrameType::User
                    },
                )
            })
            .collect();

        Self {
            pid: stack.tgid,
            tgid: stack.tgid,
            cpu_id: stack.cpu,
            cmdline: String::from_utf8_lossy(&stack.cmd)
                .trim_matches('\0')
                .to_string(),
            ts: 1,
            cycle: 1,
            stack_frames: frames,
        }
    }
}

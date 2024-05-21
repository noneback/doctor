use std::{fmt};


use cpu_profier_common::StackInfo;

pub struct PerfRecord {
    pub pid: u32,
    pub tgid: u32,
    pub cpu_id: u32,
    pub cmdline: String,
    pub ts: u64,
    pub cycle: u64,
    pub frames: Vec<PerfStackFrame>, // pub kframes: Option<Vec<PerfStackFrame>>,
                                     // pub uframes: Option<Vec<PerfStackFrame>>,
}

pub struct PerfStackFrame {
    ip: u64,
    pub sym: String,
    elf: String,
}

impl PerfStackFrame {
    pub fn new(ip: u64, sym: String, elf: String) -> Self {
        Self {
            ip,
            sym,
            elf,
        }
    }
}

impl fmt::Display for PerfRecord {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut format_str = format!("{} {} {}\n", self.pid, self.cpu_id, self.cmdline);
        for frame in &self.frames {
            format_str
                .push_str(format!("    0x{:x} {}({})\n", frame.ip, frame.sym, frame.elf).as_str());
        }
        write!(f, "{}", format_str)
    }
}

impl PerfRecord {
    pub fn from(
        stack: &StackInfo,
        kframe: Option<Vec<PerfStackFrame>>,
        uframe: Option<Vec<PerfStackFrame>>,
    ) -> Self {
        let frames = match (kframe, uframe) {
            (Some(kernel_stacks), None) => kernel_stacks,
            (None, Some(user_stacks)) => user_stacks,
            (Some(kernel_stacks), Some(user_stacks)) => kernel_stacks
                .into_iter()
                .chain(user_stacks)
                .collect::<Vec<_>>(),
            (None, None) => Vec::default(),
        };

        Self {
            pid: stack.pid,
            tgid: stack.tgid,
            cpu_id: stack.cpu,
            cmdline: String::from_utf8_lossy(&stack.cmd).to_string(),
            ts: 0,
            cycle: 1,
            frames,
        }
    }
}

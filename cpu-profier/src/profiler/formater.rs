use aya::maps::stack_trace::StackTrace;
use cpu_profier_common::StackInfo;
use log::info;

use super::translate::Translator;

pub fn format(
    translator: &mut Translator,
    stack: &StackInfo,
    trace: &StackTrace,
    is_kernel: bool,
) -> String {
    // pid/cpu_id/cmdline/[k] or [u]/stack_id
    let mut format_str: String = "".into();
    let padding: String = std::iter::repeat(' ').take(4).collect();

    if is_kernel {
        if let Some(id) = stack.kernel_stack_id {
            for frame in trace.frames().iter() {
                let addr = frame.ip;
                match translator.translate_ksyms(addr) {
                    Ok(sym) => format_str
                        .push_str(format!("\n{}0x{:x} {}_[k]", padding, addr, sym).as_str()),
                    Err(e) => {
                        info!("translate_usyms -> {}", e);
                        continue;
                    }
                }
                return format_str;
            }
        }

        if let Some(id) = stack.user_stack_id {
            for frame in trace.frames().iter() {
                let addr = frame.ip;
                match translator.translate_usyms(stack,addr) {
                    Ok(sym) => format_str
                        .push_str(format!("\n{}0x{:x} {}_[k]", padding, addr, sym).as_str()),
                    Err(e) => {
                        info!("translate_usyms -> {}", e);
                        continue;
                    }
                }
            }
            return format_str;
        }
    }

    format_str
}

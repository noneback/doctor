use aya::maps::stack_trace::StackTrace;
use cpu_profier_common::StackInfo;

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
            trace.frames().iter().for_each(|frame| {
                let addr = frame.ip;
                format_str.push_str(
                    format!(
                        "\n{}0x{:x} {}_[k]",
                        padding,
                        addr,
                        translator.translate_ksyms(addr).unwrap()
                    )
                    .as_str(),
                );
            });
            return format_str;
        }
    }

    if let Some(id) = stack.user_stack_id {
        trace.frames().iter().for_each(|frame| {
            let addr = frame.ip;
            format_str.push_str(
                format!(
                    "\n{}0x{:x} {}_[u]",
                    padding,
                    addr,
                    translator.translate_usyms(stack, addr).unwrap()
                )
                .as_str(),
            );
        });
    }

    format_str
}

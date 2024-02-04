use cpu_profier_common::StackInfo;

use super::translate::Translator;





pub fn format(translator:&mut Translator,stack: &StackInfo) -> String {
    // pid/cpu_id/cmdline/[k] or [u]/stack_id
    let mut format_str = format!(
        "{} cpu_{} {}",
        stack.tgid,
        stack.cpu,
        String::from_utf8_lossy(&stack.cmd).trim_matches('\0')
    );

    if let Some(id) = stack.kernel_stack_id {
        format_str.push_str(&format!(" [k] 0x{:x} ", id));
        format_str.push_str(translator.translate_ksyms(stack).unwrap().as_str());
    }

    if let Some(id) = stack.user_stack_id {
        format_str.push_str(&format!(" [u] 0x{:x}", id));
    }
    format_str
}



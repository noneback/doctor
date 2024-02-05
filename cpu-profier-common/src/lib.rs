#![no_std]

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
#[repr(C)]
pub struct StackInfo {
    pub tgid: u32, // thread group id
    pub pid: u32,
    pub user_stack_id: Option<i32>,
    pub kernel_stack_id: Option<i32>,
    pub cmd: [u8; 16],
    pub cpu: u32,
}

/* Global configuration */
#[no_mangle]
static SKIP_IDLE: u8 = 0;

pub unsafe fn skip_idle() -> bool {
    let skip = core::ptr::read_volatile(&SKIP_IDLE);  // TODO: why we need this?
    skip > 0
}

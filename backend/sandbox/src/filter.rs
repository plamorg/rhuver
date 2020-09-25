extern crate seccomp_sys;

use seccomp_sys::*;
use nix::libc::*;

// Wrapper around C function invocations that return < 0 on error.

const ALLOWED_SYSCALLS_LENGTH: usize = 65;
const ALLOWED_SYSCALLS: [i64; ALLOWED_SYSCALLS_LENGTH] = [
    // file descriptor stuff
    SYS_write,
    SYS_read,
    SYS_open,
    SYS_openat,
    SYS_close,
    SYS_lseek,
    SYS_dup,
    SYS_dup2,
    SYS_dup3,
    SYS_select,
    SYS_poll,
    SYS_readv,
    SYS_writev,
    SYS_preadv,
    SYS_pwritev,
    SYS_preadv2,
    SYS_pwritev2,
    SYS_pread64,
    SYS_pwrite64,

    // misc IO
    SYS_ioctl,

    // file / directory stuff
    SYS_fstat,
    SYS_stat,
    SYS_lstat,
    SYS_fcntl,
    SYS_access,
    SYS_futex,
    SYS_readlink,
    SYS_getdents,
    SYS_getdents64,
    SYS_fsync,
    SYS_newfstatat,
    SYS_faccessat,

    // permissions
    SYS_getcwd,
    SYS_getdents64,
    SYS_getegid,
    SYS_geteuid,
    SYS_getgid,
    SYS_getuid,
    SYS_getpgrp,
    SYS_setpgid,
    SYS_getrlimit,
    SYS_getresuid,
    SYS_getresgid,
    SYS_getppid,
    SYS_getgroups,
    SYS_getitimer,
    SYS_getsid,

    // time
    SYS_gettimeofday,
    SYS_clock_getres,
    SYS_clock_gettime,

    // memory
    SYS_mmap,
    SYS_munmap,
    SYS_brk,
    SYS_mprotect,
    SYS_madvise,
    /* looks very complicated to track so i don't want to */
    // SYS_mbind,
    SYS_mincore,
    
    // misc
    SYS_arch_prctl,
    SYS_exit,
    SYS_exit_group,
    SYS_execve,
    SYS_sysinfo,
    SYS_getrandom,
    SYS_set_robust_list,
    SYS_set_tid_address,
    SYS_uname,
];

pub fn filter_syscalls() -> Result<(), String> {
    let ctx = unsafe { seccomp_init(SCMP_ACT_ERRNO(libc::EPERM as u32)) };
    if ctx.is_null() {
        return Err("failed seccomp_init".to_string());
    }
    for syscall in ALLOWED_SYSCALLS.iter() {
        if unsafe { seccomp_rule_add(ctx, SCMP_ACT_ALLOW, *syscall as i32, 0) } < 0 {
            return Err(format!("failed to allow syscall nr {}", *syscall));
        }
    }
    if unsafe { seccomp_load(ctx) } < 0 {
        return Err("failed to load ctx".to_string());
    }
    Ok(())
}

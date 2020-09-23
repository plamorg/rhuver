use nix::sys::ptrace::*;
use nix::unistd::Pid;
use nix::sys::wait::*;
use nix::libc;
use std::error::Error;
use std::convert::From;
use nix::sys::signal::Signal;

pub fn trace_me(){
    traceme();
}

#[derive(PartialEq, Eq, Copy, Clone)]
pub enum Verdict {
    RuntimeError(Signal),
    TimeLimitExceeded,
    MemoryLimitExceeded,
    Ok,
    Running
}

#[derive(PartialEq, Eq, Copy, Clone)]
pub struct ProcState {
    verdict: Verdict,
    max_time: u64,
    max_mem: u64,
}

fn wait_with_sig() -> Result<Verdict, String> {
    match wait() { 
        Err(s) => Err(s.to_string()),
        Ok(stat) => 
            match stat {
                WaitStatus::Exited(_, code) => Ok(Verdict::Ok),
                WaitStatus::Signaled(_, sig, _) => Ok(Verdict::RuntimeError(sig)),
                _ => Ok(Verdict::Running)
            }
    }
}

pub fn track_memory(pid: Pid) -> Result<ProcState, String> {
    let mut state = ProcState {
        verdict: Verdict::Ok,
        max_time: 0,
        max_mem: 0,
    };
    let last_brk: u64 = 0;
    loop {
        // syscall has been entered
        if wait_with_sig()? { return Ok(state); }
        let regs = match getregs(pid) { Err(s) => Err(s.to_string()), Ok(r) => Ok(r) }?;
        let syscall_nr = regs.orig_rax;
        // wait for exit
        syscall(pid, None);
        if wait_with_sig()? { return Ok(state); }
        match syscall_nr as i64 {
            libc::SYS_brk => {
                if last_brk == 0 && regs.rbx != 0 {
                    return Err("called brk() without initial query".to_string());
                }
            },
            libc::SYS_mmap => {
            }
        }
    };
}

use nix::{sys::{ptrace, wait::*, signal::{kill, Signal, raise}}, unistd::Pid, libc::ENOMEM};
use crate::proc_data::*;

pub fn trace_me() -> Result<(), nix::Error> {
    ptrace::traceme()?;
    // wait for ptracer to catch it
    raise(Signal::SIGSTOP)?;
    Ok(())
}

pub fn wait_with_sig() -> Result<Verdict, nix::Error> {
    match wait()? {
        WaitStatus::Exited(_, code) => match code {
            EXIT_CODE_FAILED_EXEC => Ok(Verdict::FailedExec),
            0 => Ok(Verdict::Ok),
            _ => Ok(Verdict::Nzec(code))
        },
        WaitStatus::Signaled(_, sig, _) => match sig {
            Signal::SIGXCPU => Ok(Verdict::TimeLimitExceeded),
            _ => Ok(Verdict::RuntimeError(sig)),
        },
        _ => Ok(Verdict::Running)
    }
}

fn log_kill(p: Pid){
    /* The reason why the result is """ignored"""
     * is that this function cannot fail
     * in an undesirable way.
     * kill(2) manpage says that the only
     * errors are EINVAL (not possible),
     * EPERM (not possible without a
     * serious bug, and cannot be fixed),
     * and ESRCH (not possible unless the
     * child has already exited / is a zombie,
     * in which case it doesn't matter.)
     */
    match kill(p, Signal::SIGKILL) { 
        Err(p) => eprintln!("Cannot SIGKILL child! {}", p),
        Ok(_) => {}
    }
}

/* Panics if it fails to SIGKILL the child. */
pub fn track_process(pid: Pid) -> ProcState {
    let mut state = ProcState {
        verdict: Verdict::Running,
        max_mem: 0,
        max_time: 0
    };
    if let Err(e) = track_process_loop(pid, &mut state) {
        log_kill(pid);
        state.verdict = Verdict::Killed(e);
    }
    state
}

fn track_process_loop(pid: Pid, state: &mut ProcState) -> Result<(), KillReason> {
    state.verdict = wait_with_sig()?;
    if state.verdict != Verdict::Running { return Ok(()); }
    ptrace::setoptions(pid, ptrace::Options::PTRACE_O_EXITKILL)?;
    ptrace::syscall(pid, None)?;

    let mut last_brk: u64 = 0;
    loop {
        // syscall has been entered
        state.verdict = wait_with_sig()?;
        if state.verdict != Verdict::Running { return Ok(()); }
        let syscall_nr = ptrace::getregs(pid)?.orig_rax;
        // wait for exit
        ptrace::syscall(pid, None)?;
        state.verdict = wait_with_sig()?;
        if state.verdict != Verdict::Running { return Ok(()); }
        let regs = ptrace::getregs(pid)?;
        if syscall_nr == libc::SYS_execve {
        }
        if (regs.rax as i64) <= 0 { // syscall failed
            // check for ENOMEM
            if regs.rax == ((-ENOMEM) as u64) {
                log_kill(pid);
                state.verdict = Verdict::MemoryLimitExceeded;
                return Ok(());
            }
        } else { // syscall succeeded, check what it tried to do
            match syscall_nr as i64 {
                libc::SYS_brk => {
                    if last_brk == 0 {
                        if regs.rdi != 0 {
                            return Err(KillReason::BrkWithoutInitialCall);
                        }
                        last_brk = regs.rdi;
                    }
                    // safe because of 2's complement
                    state.max_mem += regs.rdi - last_brk;
                    last_brk = regs.rdi;
                },
                libc::SYS_mmap => {
                    state.max_mem += regs.rdi;
                },
                libc::SYS_mremap => {
                    // safe because of 2's complement
                    state.max_mem += regs.rsi - regs.rdi;
                },
                libc::SYS_munmap => {
                    state.max_mem -= regs.rdi;
                },
                _ => {} /* we don't need to monitor any others */
            }
        }
    };
}

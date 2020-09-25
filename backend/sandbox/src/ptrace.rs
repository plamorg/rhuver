use nix::{sys::{ptrace::*, wait::*, signal::{kill, Signal}}, unistd::Pid, libc};
use crate::proc_data::*;

pub fn trace_me() -> Result<(), nix::Error> {
    traceme()
}

fn wait_with_sig() -> Result<Verdict, nix::Error> {
    match wait()? {
        WaitStatus::Exited(_, code) => match code {
            EXIT_CODE_FAILED_EXEC => Ok(Verdict::FailedExec),
            _ => Ok(Verdict::Ok)
        },
        WaitStatus::Signaled(_, sig, _) => Ok(Verdict::RuntimeError(sig)),
        _ => Ok(Verdict::Running)
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
        /* The reason why the result is """ignored"""
         * is that this function cannot fail
         * in an undesirable way.
         * kill(2) manpage says that the only
         * errors are EINVAL (not possible),
         * EPERM (not possible without a
         * serious bug, and cannot be fixed),
         * and ESRCH (not possible unless the
         * child hss already exited / is a zombie,
         * in which case it doesn't matter.)
         */
        match kill(pid, Signal::SIGKILL) { 
            Err(p) => eprintln!("Cannot SIGKILL child! {}", p),
            Ok(_) => {}
        }
        state.verdict = Verdict::Killed(e);
    }
    state
}

fn track_process_loop(pid: Pid, state: &mut ProcState) -> Result<(), KillReason> {
    let mut last_brk: u64 = 0;
    loop {
        // syscall has been entered
        state.verdict = wait_with_sig()?;
        if state.verdict != Verdict::Running { return Ok(()); }
        let syscall_nr = getregs(pid)?.orig_rax;
        // wait for exit
        syscall(pid, None)?;
        state.verdict = wait_with_sig()?;
        if state.verdict != Verdict::Running { return Ok(()); }
        let regs = getregs(pid)?;
        match syscall_nr as i64 {
            // filter if allocation worked
            libc::SYS_brk if (regs.rax as i64) >= 0 => {
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
            libc::SYS_mmap if (regs.rax as i64) >= 0 => {
                state.max_mem += regs.rdi;
            },
            libc::SYS_mremap if (regs.rax as i64) >= 0 => {
                // safe because of 2's complement
                state.max_mem += regs.rsi - regs.rdi;
            },
            libc::SYS_munmap if (regs.rax as i64) >= 0 => {
                state.max_mem -= regs.rdi;
            },
            _ => {} /* we don't need to monitor any others */
        }
    };
    // TODO: rlimit
}

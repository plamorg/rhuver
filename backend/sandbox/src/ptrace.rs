use nix::{sys::{ptrace::*, wait::*, signal::{kill, Signal}}, unistd::Pid, libc};
use crate::proc_data::*;

pub fn trace_me(){
    traceme();
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

pub fn track_process(pid: Pid) -> ProcState {
    let state = ProcState {
        verdict: Verdict::Running,
        max_mem: 0,
        max_time: 0
    };
    if let Err(e) = track_process_loop(pid, &mut state) {
        kill(pid, Signal::SIGKILL);
        state.verdict = Verdict::Killed(e);
    }
    state
}

fn track_process_loop(pid: Pid, state: &mut ProcState) -> Result<(), KillReason> {
    let last_brk: u64 = 0;
    loop {
        // syscall has been entered
        state.verdict = wait_with_sig()?;
        if state.verdict != Verdict::Running { return Ok(()); }
        let regs = getregs(pid)?;
        let syscall_nr = regs.orig_rax;
        // wait for exit
        syscall(pid, None);
        state.verdict = wait_with_sig()?;
        if state.verdict != Verdict::Running { return Ok(()); }
        match syscall_nr as i64 {
            libc::SYS_brk => {
                if last_brk == 0 && regs.rbx != 0 {
                    return Err(KillReason::BrkWithoutInitialCall);
                }
            },
            libc::SYS_mmap => {
                // TODO
            }
        }
    };
    // TODO
}

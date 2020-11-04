use nix::{errno, sys::{ptrace, wait::*, signal::{sigaction, SigHandler, SigAction, SaFlags, SigSet, kill, Signal, raise}}, unistd::{Pid, alarm}};
use std::{time::Instant, os::unix::io::RawFd, convert::TryInto};
use crate::{link, proc_data::*};

pub fn trace_me() -> Result<(), nix::Error> {
    ptrace::traceme()?;
    // wait for ptracer to catch it
    raise(Signal::SIGSTOP)?;
    Ok(())
}

pub fn wait_with_sig(could_fail_exec: bool, child_pid: Pid) -> Result<Verdict, nix::Error> {
    let res = match waitpid(child_pid, None) {
        Ok(p) => p,
        Err(e) => {
            println!("err: {}", e);
            return Err(e);
        }
    };
    println!("child_pid: {}, res: {:?}", child_pid, res);
    match res {
        WaitStatus::Exited(_, code) => match code {
            EXIT_CODE_FAILED_EXEC if could_fail_exec => Ok(Verdict::FailedExec),
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

/* Logs if it fails to SIGKILL the child. */
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

pub fn track_process(pid: Pid, reader: RawFd, time_limit: u64, mem_limit: u64) -> ProcState {
    let mut state = ProcState {
        verdict: Verdict::Running,
        max_mem: 0,
        max_time_ms: 0
    };
    let start_time = Instant::now();
    if let Err(e) = track_process_loop(pid, &mut state, reader, time_limit, mem_limit) {
        log_kill(pid);
        if e == KillReason::Sys(nix::Error::Sys(errno::Errno::EINTR)) {
            // if it died with EINTR, then 
            // it got SIGALRMed
            state.verdict = Verdict::TimeLimitExceeded;
        } else {
            state.verdict = Verdict::Killed(e);
        }
    }
    /* I converted as_millis() from u128 to u64,
     * because exceeding the u64 limit will never happen, 
     * and if it does, we have other problems (such as an AWS cost in the hundreds of trillions of USD.)
     */
    state.max_time_ms = start_time.elapsed().as_millis().try_into().unwrap();
    state
}
/* Required so that EINTR can be returned from waitpid().
 * (Oh man, some Unix design choices are really bad...)
 */
extern fn handle_sigalrm(_: nix::libc::c_int) {
    println!("Got it!");
}

fn track_process_loop(pid: Pid, state: &mut ProcState, reader: RawFd, time_limit: u64, mem_limit: u64) -> Result<(), KillReason> {
    // Makes EINTR a return possibility.
    unsafe { 
        sigaction(
            Signal::SIGALRM,
            &SigAction::new(
                SigHandler::Handler(handle_sigalrm),
                SaFlags::empty(),
                SigSet::empty()
            )
        )
    }?;
    // Set up an alarm to notify us after maxtime seconds.
    // TODO 
    // alarm::set(time_limit as u32);
    alarm::set(10);
    
    // initiate the ptrace
    state.verdict = wait_with_sig(true, pid)?;
    if state.verdict != Verdict::Running { return Ok(()); }
    ptrace::setoptions(pid, ptrace::Options::PTRACE_O_EXITKILL  |
                            ptrace::Options::PTRACE_O_TRACEEXEC | 
                            ptrace::Options::PTRACE_O_TRACESYSGOOD)?;
    // The program is currently SIGSTOPed, so SIGCONT it
    kill(pid, Signal::SIGCONT)?;
        ptrace::syscall(pid, None)?;

    let mut last_brk: u64 = 0;
    let mut could_fail_exec: bool = true;
    let mut mem_used: u64 = 0;
    loop {
        // syscall has been entered
        state.verdict = wait_with_sig(could_fail_exec, pid)?;
        if state.verdict != Verdict::Running { return Ok(()); }
        let syscall_nr = ptrace::getregs(pid)?.orig_rax;
        // wait for syscall exit
        ptrace::syscall(pid, None)?;
        state.verdict = wait_with_sig(could_fail_exec, pid)?;
        if state.verdict != Verdict::Running { 
            // it exited, figure out what happened
            if state.verdict == Verdict::FailedExec {
                // (put it in the logs)
                let mut buf = vec![0u8; 4096];
                println!("Verdict::FailedExec: {:#?}", link::read_link(reader, &mut buf));
                return Ok(());
            }
        }
        let regs = ptrace::getregs(pid)?;
        println!("syscall nr {} returned {}", syscall_nr, regs.rax);
        // println!("{:#?}", regs);
        if (regs.rax as i64) <= 0 { // syscall failed
            // check if execve() failed
            if syscall_nr == (libc::SYS_execve as u64) {
                return Err(KillReason::Sys(
                    nix::Error::from_errno(errno::from_i32(-(regs.rax as i64 as i32)))
                ));
            }
            // check for ENOMEM
            if regs.rax == ((-libc::ENOMEM) as u64) {
                log_kill(pid);
                state.verdict = Verdict::MemoryLimitExceeded;
                return Ok(());
            }
        } else { // syscall succeeded, check what it tried to do
            match syscall_nr as i64 {
                libc::SYS_execve if !could_fail_exec => {
                    could_fail_exec = false;
                },
                // memory allocation functions
                libc::SYS_brk => {
                    if last_brk == 0 {
                        if regs.rdi != 0 {
                            return Err(KillReason::BrkWithoutInitialCall);
                        }
                        last_brk = regs.rdi;
                    }
                    // safe because of 2's complement
                    mem_used += regs.rdi - last_brk;
                    last_brk = regs.rdi;
                },
                libc::SYS_mmap => {
                    mem_used += regs.rdi;
                },
                libc::SYS_mremap => {
                    // safe because of 2's complement
                    mem_used += regs.rsi - regs.rdi;
                },
                libc::SYS_munmap => {
                    mem_used -= regs.rdi;
                },
                _ => {} /* we don't need to monitor any others */
            }
            if state.max_mem < mem_used {
                state.max_mem = mem_used;
            }
        }
    };
}

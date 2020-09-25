mod filter;
mod proc_data;
mod ptrace;
mod rlimit;
use proc_data::*;

use nix::unistd::{fork, ForkResult};
use std::os::unix::process::CommandExt;
use std::process::{exit, Command};

/* Runs the arguments given as a compiler - 3 second maximum time, no maximum memory. */
/* pub fn compile(bin: String, args: Vec<String>) {
    // TODO
} */

fn limit_myself(mem_limit: u64, time_limit: u64) -> Result<(), String> {
    if let Err(p) = ptrace::trace_me() {
        return Err(p.to_string());
    }
    rlimit::limit_memtime(mem_limit, time_limit)?;
    filter::filter_syscalls()
}

/* Runs the arguments given as a submission with `time_limit` and `mem_limit`. */
pub fn exec(bin: String, args: Vec<String>, time_limit: u64, mem_limit: u64) -> ProcState {
    match fork() {
        Ok(ForkResult::Parent { child }) => {
            ptrace::track_process(child)
        },
        Ok(ForkResult::Child) => {
            match limit_myself(mem_limit, time_limit) {
                Err(_) => exit(EXIT_CODE_FAILED_EXEC),
                _ => {}
            }
            Command::new(bin)
                .args(args)
                .exec();
            // definitely errored
            exit(EXIT_CODE_FAILED_EXEC);
        },
        Err(_) => ProcState {
            max_mem: 0,
            max_time: 0,
            verdict: Verdict::FailedExec
        }
    }
}

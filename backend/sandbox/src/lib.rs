mod filter;
mod proc_data;
mod ptrace;
use proc_data::*;

use nix::unistd::{fork, ForkResult};
use std::os::unix::process::CommandExt;
use std::process::{exit, Command};

/* Runs the arguments given as a compiler - 3 second maximum time, no maximum memory. */
pub fn compile(bin: String, args: Vec<String>) {
    // TODO
}

/* Runs the arguments given as a submission with `time_limit` and `mem_limit`. */
pub fn exec(bin: String, args: Vec<String>, time_limit: u64, mem_limit: u64) -> Result<ProcState, String> {
    match fork() {
        Ok(ForkResult::Parent { child }) => {
            let result = ptrace::track_process(child);
            // TODO
        },
        Ok(ForkResult::Child) => {
            ptrace::trace_me();
            filter::filter_syscalls();
            let err = Command::new(bin)
                .args(args)
                .exec();
            // definitely errored
            exit(EXIT_CODE_FAILED_EXEC);
        }
    }
}

extern crate libc;
mod filter;
mod ptrace;

use nix::unistd::{fork, ForkResult};
use std::os::unix::process::CommandExt;
use std::process::Command;

pub fn compile(bin: String, args: Vec<String>) {
}

pub fn exec(bin: String, args: Vec<String>) -> Result<ExecRes, String> {
    match fork() {
        Ok(ForkResult::Parent { child }) => {
            ptrace::track_memory(child);
        },
        Ok(ForkResult::Child) => {
            ptrace::trace_me();
            filter::filter_syscalls();
            Command::new(bin)
                .args(args)
                .exec();
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

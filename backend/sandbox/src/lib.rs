mod filter;
mod proc_data;
mod ptrace;
mod limit;
mod link;
mod common;
use proc_data::*;

use nix::unistd::{fork, ForkResult};
use std::{io::Write, time::Instant, os::unix::{io::RawFd, process::CommandExt}, process::{exit, Command}};

fn limit_myself(mem_limit: u64, time_limit: u64) -> Result<(), String> {
    common::error_convert(ptrace::trace_me())?;
    limit::limit_memtime(mem_limit, time_limit)?;
    filter::filter_syscalls()
}

/* Will not return unless there is an error. */
fn setup_child_compiler(bin: &String, args: &Vec<String>, conn: RawFd) -> String {
    //                                 v fd for stderr */
    if let Err(p) = link::reroute_link(conn, 2) { return p; }
    if let Err(p) = limit_myself(rlimit::RLIM_INFINITY, 3) { return p; }
    Command::new(bin)
        .args(args)
        .exec();
    "failed to execute".to_string()
}

/* Runs the arguments given as a compiler - 3 second maximum time, no maximum memory.
 * Returns the amount of time taken (milliseconds) as a u64, or String on error. */
pub fn compile(bin: String, args: Vec<String>) -> Result<u64, String> {
    let conn_both = link::init_link()?;
    match fork() {
        Ok(ForkResult::Parent { child: _ }) => {
            let conn = link::read_side(conn_both);
            // wait for child to exit
            let child_start_time = Instant::now();
            let res = common::error_convert(ptrace::wait_with_sig())?;
            let mut buf = Vec::with_capacity(4096);
            let nr_read = link::read_link(conn, &mut buf)?;
            println!("{}", nr_read);
            buf.resize(nr_read, 0);
            let msg = String::from_utf8_lossy(&buf).to_string();
            match res {
                Verdict::Nzec(_) | Verdict::RuntimeError(_) => {
                    // failed to compile
                    Err(msg)
                },
                Verdict::FailedExec => {
                    if msg.len() == 0 {
                        Err("failed to execute: no further details".to_string())
                    } else {
                        Err(msg)
                    }
                },
                Verdict::TimeLimitExceeded => {
                    Err("Took too long to compile".to_string())
                },
                _ => {
                    Ok(child_start_time.elapsed().as_millis() as u64)
                }
            }
        },
        Ok(ForkResult::Child) => {
            let conn = link::write_side(conn_both);
            let err = setup_child_compiler(&bin, &args, conn);
            // if the above returned, it definitely errored
            // there's not much we can do about the link failing anyway; so ignore the result
            let _ = link::write_link(conn, format!("failed to execute: {}", err).as_bytes());
            exit(EXIT_CODE_FAILED_EXEC);
        },
        Err(p) => Err(format!("Failed to fork(): {}", p))
    }
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
                Ok(_) => {}
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

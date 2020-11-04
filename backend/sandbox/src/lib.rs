mod filter;
mod proc_data;
mod trace;
mod limit;
mod link;
mod common;
pub use proc_data::*;
use common::error_convert;

use nix::{unistd::{alarm, fork, ForkResult, execve}, libc::{SYS_vfork, SYS_fork, SYS_clone}, fcntl::OFlag};
use std::{time::Instant, os::unix::io::RawFd, process::exit, ffi::{CString, CStr}, convert::Infallible};

fn execute_with_err(bin: &String, args: &Vec<String>) -> Result<Infallible, String> {
    /* execve() needs `CStr`s and $PATH, and it's needed twice, 
     * so it's pulled off into this function.
     */
    // Turn everything into `CString`s.
    let cstr_bin = error_convert( CString::new(bin.as_str()) )?;
    let cstr_args = error_convert(
        args.iter()
        .map(|x| CString::new(x.as_str()))
        .collect::<Result<Vec<_>, _>>()
    )?;
    let cstr_path = error_convert( CString::new("PATH=".to_string() + env!("PATH")) )?;
    // Call execve.
    error_convert(
        execve(
            cstr_bin.as_c_str(),
            &(cstr_args.iter().map(|x| x.as_c_str()).collect::<Vec<&CStr>>()),
            &[cstr_path.as_c_str()]
        )
    )
}

/* Will not return unless there is an error. */
fn setup_child_compiler(bin: &String, args: &Vec<String>, conn: RawFd) -> Result<Infallible, String> {
    link::reroute_link(conn, 2)?; // reroute stderr to link
    limit::limit_memtime(rlimit::RLIM_INFINITY, 3)?;
    filter::filter_syscalls(&[SYS_vfork, SYS_fork, SYS_clone])?;
    // if it passed the execve it definitely errored
    let err = execute_with_err(bin, args).unwrap_err();
    Err(format!("could not execute with error {}", err))
}

/* Runs the arguments given as a compiler - 3 second maximum time, no maximum memory.
 * Returns the amount of time taken (milliseconds) as a u64, or String on error. */
pub fn compile(bin: String, args: Vec<String>) -> Result<u64, String> {
    let conn_both = link::init_link()?;
    match fork() {
        Ok(ForkResult::Parent { child: pid }) => {
            let conn = link::read_side(conn_both);
            // wait for child to exit
            let child_start_time = Instant::now();
            let mut res;
            while {
                res = error_convert(trace::wait_with_sig(true, pid))?;
                res == Verdict::Running
            } {};
            let mut buf = vec![0u8; 4096];
            let _ = link::close_side(link::write_side(conn_both));
            let nr_read = link::read_link(conn, &mut buf)?;
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
            let err = setup_child_compiler(&bin, &args, conn).unwrap_err();
            // if the above returned, it definitely errored
            // there's not much we can do about the link failing anyway; so ignore the result
            let _ = link::write_link(conn, format!("failed to launch compiler: {}", err).as_bytes());
            let _ = link::close_side(conn);
            exit(EXIT_CODE_FAILED_EXEC);
        },
        Err(p) => Err(format!("Failed to fork(): {}", p))
    }
}

fn setup_gradee(bin: &String, args: &Vec<String>, mem_limit: u64, time_limit: u64) -> Result<Infallible, String> {
    error_convert(trace::trace_me())?;
    limit::limit_memtime(mem_limit, time_limit)?;
    filter::filter_syscalls(&[])?;
    // if it passed this, it definitely errored
    execute_with_err(bin, args)
}

/* Runs the arguments given as a submission with `time_limit` and `mem_limit`. */
pub fn exec(bin: String, args: Vec<String>, time_limit: u64, mem_limit: u64) -> Result<ProcState, String> {
    let (reader, writer) = link::init_link_flag(OFlag::O_CLOEXEC)?;
    match fork() {
        Ok(ForkResult::Parent { child }) => {
            Ok(trace::track_process(child, reader, time_limit, mem_limit))
        },
        Ok(ForkResult::Child) => {
            // if this returns, it definitely errored
            let err = setup_gradee(&bin, &args, mem_limit, time_limit).unwrap_err();
            // try to write it to link, but if it fails there's nothing we can do
            let _ = link::write_link(writer, format!("failed to launch submission: {}", err).as_bytes());
            let _ = link::close_side(writer);
            exit(EXIT_CODE_FAILED_EXEC);
        },
        Err(_) => Err("failed to fork".to_string())
    }
}

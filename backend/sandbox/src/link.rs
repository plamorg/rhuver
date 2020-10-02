/* Links parent and child process together through pipes. */

use nix::{unistd::{close, pipe, pipe2, dup2, write, read}, fcntl::{open, OFlag}, sys::stat::Mode};
use std::os::unix::io::RawFd;
use crate::common::*;

#[allow(dead_code)]
pub fn get_tmpfile() -> Result<RawFd, String> {
    error_convert(open(".", OFlag::O_TMPFILE, Mode::S_IRWXU))
}

pub fn reroute_link(to: RawFd, from: RawFd) -> Result<RawFd, String> {
    error_convert(dup2(to, from))
}

/* Initiates a parent <-> child communication link. */
pub fn init_link() -> Result<(RawFd, RawFd), String> {
    error_convert(pipe())
}

pub fn init_link_flag(flags: OFlag) -> Result<(RawFd, RawFd), String> {
    error_convert(pipe2(flags))
}

pub fn write_link(conn: RawFd, msg: &[u8]) -> Result<usize, String> {
    error_convert(write(conn, msg))
}

pub fn read_link(conn: RawFd, buf: &mut[u8]) -> Result<usize, String> {
    error_convert(read(conn, buf))
}

pub fn write_side(fds: (RawFd, RawFd)) -> RawFd {
    fds.1
}

pub fn read_side(fds: (RawFd, RawFd)) -> RawFd {
    fds.0
}

pub fn close_side(fd: RawFd)  -> Result<(), String> {
    error_convert(close(fd))
}

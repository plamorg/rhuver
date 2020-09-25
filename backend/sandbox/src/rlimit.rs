use rlimit::*;
use std::io;

pub fn limit_memtime(max_mem: u64, max_sec: u64) -> Result<(), String> {
    match limit_memtime_raw(max_mem, max_sec) {
        Err(s) => Err(s.to_string()),
        Ok(p) => Ok(p)
    }
}

fn limit_memtime_raw(max_mem: u64, max_sec: u64) -> io::Result<()> {
    setrlimit(Resource::AS, max_mem, max_mem)?;
    setrlimit(Resource::CORE, 0, 0)?;
    setrlimit(Resource::CPU, max_sec, max_sec + 1)
}

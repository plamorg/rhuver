use nix::sys::signal::Signal;
use std::error::Error;
use std::fmt;
use std::convert::From;

/* Exit code of the process that is returned when it failed to execute. 
 * (62 was chosen at random.)
 */
pub const EXIT_CODE_FAILED_EXEC: i32 = 62;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum KillReason {
    BrkWithoutInitialCall,
    Sys(nix::Error),
}

impl fmt::Display for KillReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KillReason::BrkWithoutInitialCall => 
                write!(f, "called brk() without initial brk(NULL)"),
            KillReason::Sys(err) =>
                write!(f, "{}", err)
        }
    }
}

impl From<nix::Error> for KillReason {
    fn from(err: nix::Error) -> KillReason {
        KillReason::Sys(err)
    }
}

impl Error for KillReason {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            KillReason::BrkWithoutInitialCall => None,
            KillReason::Sys(e) => Some(e)
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Verdict {
    RuntimeError(Signal),
    TimeLimitExceeded,
    MemoryLimitExceeded,
    Killed(KillReason),
    FailedExec,
    Ok,
    Running
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct ProcState {
    pub verdict: Verdict,
    pub max_time: u64,
    pub max_mem: u64,
}

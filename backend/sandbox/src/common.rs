use std::error::Error;

pub fn error_convert<T, E: Error>(res: Result<T, E>) -> Result<T, String> {
    match res {
        Err(p) => Err(p.to_string()),
        Ok(p) => Ok(p)
    }
}

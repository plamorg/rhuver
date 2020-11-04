extern crate sandbox;


fn exec_test(path: String, cpp: String, exec_name: &'static str) -> sandbox::Verdict {
    use std::thread;
    use std::sync::mpsc;
    // Due to the way `cargo test` works,
    // we need to set up a "clean" environment to test in.
    // This does exactly that.
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        sandbox::compile("/usr/bin/g++".to_string(), vec!["g++", "-O2", "-w", &cpp, "-o", exec_name].iter().map(|x| x.to_string()).collect::<Vec<String>>()).unwrap();
        let ret = sandbox::exec(format!("{}/{}", path, exec_name), vec![], 1, 1024 * 1024).unwrap().verdict;
        tx.send(ret).unwrap();
        std::process::exit(0);
    });
    rx.recv().unwrap()
}

#[test]
pub fn run_normal() {
    let path: String = env!("CARGO_MANIFEST_DIR").to_string();
    let cpp = format!("{}/tests/network.cpp", path);
    assert_eq!(exec_test(path, cpp, "network.x86_64"), sandbox::Verdict::Ok);
}

#[test]
pub fn run_mle() {
    let path: String = env!("CARGO_MANIFEST_DIR").to_string();
    let cpp = format!("{}/tests/mle.cpp", path);
    assert_eq!(exec_test(path, cpp, "mle.x86_64"), sandbox::Verdict::MemoryLimitExceeded);
}

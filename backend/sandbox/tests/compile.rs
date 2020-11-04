extern crate sandbox;

#[test]
fn compile_test_success() {
    let path: String = env!("CARGO_MANIFEST_DIR").to_string() + "/tests/test_compile.cpp";
    sandbox::compile("/usr/bin/g++".to_string(), vec!["g++", "-std=c++17", "-O2", "-w", &path, "-o", "test.x86_64"].iter().map(|x| x.to_string()).collect::<Vec<String>>()).unwrap();
    // sandbox::compile("/usr/bin/env".to_string(), vec!["env"].iter().map(|x| x.to_string()).collect()).unwrap();
}

#[test]
fn compile_test_fail() {
    let path: String = env!("CARGO_MANIFEST_DIR").to_string() + "/tests/compile.rs";
    sandbox::compile("/usr/bin/g++".to_string(), vec!["g++", "-std=c++17", "-O2", "-w", &path, "-o", "test_fail.x86_64"].iter().map(|x| x.to_string()).collect::<Vec<String>>()).unwrap_err();
}

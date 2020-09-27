extern crate sandbox;

#[test]
fn compile_test() {
    sandbox::compile("/usr/bin/g++".to_string(), vec!["g++", "-std=c++17", "-O2", "-w"].iter().map(|x| x.to_string()).collect::<Vec<String>>()).unwrap();
}

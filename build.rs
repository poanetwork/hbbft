extern crate protoc_rust;

use std::env;

fn protoc_exists() -> bool {
    let name = "PATH";
    match env::var_os(name) {
        Some(paths) => {
            for path in env::split_paths(&paths) {
                if path.join("protoc").exists() {
                    return true;
                }
            }
        }
        None => println!("PATH environment variable is not defined."),
    }
    false
}

fn main() {
    if !protoc_exists() {
        panic!(
            "
protoc cannot be found. Install the protobuf compiler in the \
system path."
        );
    } else {
        println!("cargo:rerun-if-changed=proto/message.proto");
        protoc_rust::run(protoc_rust::Args {
            out_dir: "src/proto",
            input: &["proto/message.proto"],
            includes: &["proto"],
        }).expect("protoc");
    }
}

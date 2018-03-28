extern crate protoc_rust;

fn main() {
    println!("cargo:rerun-if-changed=proto/message.proto");
    protoc_rust::run(protoc_rust::Args {
        out_dir: "src/proto",
        input: &["proto/message.proto"],
        includes: &["proto"],
    }).expect("protoc");
}

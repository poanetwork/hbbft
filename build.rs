#[cfg(feature = "serialization-protobuf")]
mod feature_protobuf {
    extern crate protobuf_codegen_pure;

    pub fn main() {
        println!("cargo:rerun-if-changed=proto/message.proto");
        protobuf_codegen_pure::run(protobuf_codegen_pure::Args {
            out_dir: "src/proto",
            input: &["proto/message.proto"],
            includes: &["proto"],
            customize: Default::default(),
        }).expect("protoc");
    }
}

#[cfg(feature = "serialization-protobuf")]
fn main() {
    feature_protobuf::main()
}

#[cfg(not(feature = "serialization-protobuf"))]
fn main() {}

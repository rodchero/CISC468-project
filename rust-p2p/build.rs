use std::io::Result;

fn main() -> Result<()> {
    // This tells cargo to re-run this build script ONLY if the .proto file changes.
    println!("cargo:rerun-if-changed=proto/p2pfileshare.proto");
    
    // Compile the .proto file into Rust code.
    // The generated file will be hidden in the `target/` directory.
    prost_build::compile_protos(&["proto/p2pfileshare.proto"], &["proto/"])?;
    
    Ok(())
}
use std::io::Result;

const PROTOBUF_BASE_DIRECTORY: &str = "src/proto/specs";
const PROTOBUF_FILES: [&str; 1] = ["types"];

fn build_protobufs() -> Result<()> {
    let files = PROTOBUF_FILES.map(|file| format!("{PROTOBUF_BASE_DIRECTORY}/{file}.proto"));
    prost_build::compile_protos(&files, &[PROTOBUF_BASE_DIRECTORY])?;
    Ok(())
}

fn main() -> Result<()> {
    build_protobufs()?;
    Ok(())
}

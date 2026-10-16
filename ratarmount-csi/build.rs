fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/csi.proto");
    let descriptors = protox::compile(["proto/csi.proto"], ["proto"])?;
    tonic_build::configure().compile_fds(descriptors)?;
    Ok(())
}

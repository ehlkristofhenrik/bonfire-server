use std::error::Error;
use std::fs::copy;

fn main() -> Result<(), Box<dyn Error>> {
    copy("static/config.json", "config.json").unwrap();
    tonic_build::compile_protos("proto/secu_score.proto")?;
    Ok(())
}

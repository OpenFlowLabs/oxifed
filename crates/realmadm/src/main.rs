use miette::{Context, IntoDiagnostic, Result};
use rsa::{
    pkcs1::{EncodeRsaPrivateKey, LineEnding},
    RsaPrivateKey,
};
use std::io::Write;
use std::{fs::File, path::Path};

fn main() -> Result<()> {
    let mut rng = rand::thread_rng();
    let bits = 4096;
    let priv_key = RsaPrivateKey::new(&mut rng, bits)
        .into_diagnostic()
        .wrap_err("could not generate Private key")?;

    let pem_key = priv_key
        .to_pkcs1_pem(LineEnding::LF)
        .into_diagnostic()
        .wrap_err("could not convert key to pkcs1")?;
    let pem_path = Path::new("keys").join("master.pem");

    let mut pem_file = File::create(pem_path)
        .into_diagnostic()
        .wrap_err("could not open file handle")?;
    pem_file
        .write_all(pem_key.as_bytes())
        .into_diagnostic()
        .wrap_err("could not write key")?;

    Ok(())
}

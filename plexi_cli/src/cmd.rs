use std::{fs, io};

use anyhow::{anyhow, Result};
use ed25519_dalek::{ed25519::signature::SignerMut, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};
use plexi_core::{SignatureMessage, SignatureResponse};

pub fn file_or_stdin(input: Option<String>) -> Result<Box<dyn io::Read>> {
    let reader: Box<dyn io::Read> = match input {
        Some(path) => Box::new(io::BufReader::new(
            fs::File::open(path).map_err(|_e| anyhow!("cannot read input file"))?,
        )),
        None => Box::new(io::BufReader::new(io::stdin())),
    };
    Ok(reader)
}

pub fn file_or_stdout(output: Option<String>) -> Result<Box<dyn io::Write>> {
    let writer: Box<dyn io::Write> = match output {
        Some(path) => Box::new(io::BufWriter::new(
            fs::File::create(path).map_err(|_e| anyhow!("cannot create output file"))?,
        )),
        None => Box::new(io::BufWriter::new(io::stdout())),
    };
    Ok(writer)
}

pub fn sign(signingkey: &str, output: Option<String>, input: Option<String>) -> Result<String> {
    let src = file_or_stdin(input)?;
    let dst = file_or_stdout(output)?;

    let secret_key: [u8; SECRET_KEY_LENGTH] = hex::decode(signingkey)
        .map_err(|_e| anyhow!("cannot decode signing key"))?
        .as_slice()
        .try_into()
        .map_err(|_e| anyhow!("cannot convert signing key"))?;
    let mut secret_key = ed25519_dalek::SigningKey::from_bytes(&secret_key);

    let message: SignatureMessage = serde_json::from_reader(src)?;

    let signature = secret_key.sign(&message.to_vec()?);

    let signature_response = SignatureResponse::new(
        message.timestamp(),
        message.epoch(),
        message.digest(),
        signature.to_vec(),
    );

    serde_json::to_writer(dst, &signature_response)?;

    Ok("".to_string())
}

pub fn verify(publickey: &str, input: Option<String>) -> Result<String> {
    let src = file_or_stdin(input)?;

    let signature_response: SignatureResponse = serde_json::from_reader(src)?;

    let public_key: [u8; PUBLIC_KEY_LENGTH] = hex::decode(publickey)
        .map_err(|_e| anyhow!("cannot decode public key"))?
        .as_slice()
        .try_into()
        .map_err(|_e| anyhow!("cannot convert public key"))?;
    let publickey = ed25519_dalek::VerifyingKey::from_bytes(&public_key)
        .map_err(|_| anyhow!("cannot create public key"))?;

    let signature = ed25519_dalek::Signature::from_bytes(&signature_response.signature());

    let message: SignatureMessage = signature_response.into();

    publickey
        .verify_strict(&message.to_vec()?, &signature)
        .map_err(|_e| anyhow!("cannot verify signature"))?;

    Ok("Signature valid".to_string())
}

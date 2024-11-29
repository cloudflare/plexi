use std::{
    fmt, fs,
    io::{self, Read},
    path::PathBuf,
};

use akd::local_auditing::AuditBlobName;
use anyhow::{anyhow, Context, Result};
use colored::Colorize;
use log::log_enabled;
use plexi_core::{
    auditor, client::PlexiClient, namespaces::Namespaces, Ciphersuite, Epoch, SignatureResponse,
};
use reqwest::Url;

use crate::print::print_dots;

const APP_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"),);

pub fn file_or_stdin(input: Option<PathBuf>) -> Result<Box<dyn io::Read>> {
    let reader: Box<dyn io::Read> = match input {
        Some(path) => Box::new(io::BufReader::new(
            fs::File::open(path).context("cannot read input file")?,
        )),
        None => Box::new(io::BufReader::new(io::stdin())),
    };
    Ok(reader)
}

#[allow(dead_code)]
pub fn file_or_stdout(output: Option<PathBuf>) -> Result<Box<dyn io::Write>> {
    let writer: Box<dyn io::Write> = match output {
        Some(path) => Box::new(io::BufWriter::new(
            fs::File::create(path).context("cannot create output file")?,
        )),
        None => Box::new(io::BufWriter::new(io::stdout())),
    };
    Ok(writer)
}

pub async fn ls(remote_url: &str, namespace: Option<&str>, long: bool) -> Result<String> {
    let client = PlexiClient::new(Url::parse(remote_url)?, None, Some(APP_USER_AGENT))?;

    let namespaces = if let Some(namespace) = namespace {
        let mut namespaces = Namespaces::new();
        let Some(info) = client.namespace(namespace).await? else {
            return Err(anyhow!("namespace {namespace} does not exist"));
        };
        namespaces.push(info);
        namespaces
    } else {
        client.namespaces().await?
    };

    let result: Vec<String> = namespaces
        .iter()
        .map(|info| {
            if long {
                [
                    info.name().to_string().as_str(),
                    format!(
                        "  {: <11}: {status}",
                        "Status".bold(),
                        status = info.status()
                    )
                    .as_str(),
                    format!(
                        "  {: <11}: {version}",
                        "Ciphersuite".bold(),
                        version = format_ciphersuite(&info.signature_version())
                    )
                    .as_str(),
                    format!(
                        "  {: <11}: {root}",
                        "Root".bold(),
                        root = info.root().unwrap_or("-")
                    )
                    .as_str(),
                    format!(
                        "  {: <11}: {directory}",
                        "Directory".bold(),
                        directory = info.log_directory().unwrap_or("-")
                    )
                    .as_str(),
                    "\n",
                ]
                .join("\n")
            } else {
                info.name().to_string()
            }
        })
        .collect();

    Ok(result.join("\n"))
}

fn format_ciphersuite(ciphersuite: &Ciphersuite) -> String {
    match ciphersuite {
        Ciphersuite::BincodeEd25519 => "ed25519(bincode)".to_string(),
        Ciphersuite::ProtobufEd25519 => "ed25519(protobuf)".to_string(),
        Ciphersuite::Unknown(u) => format!("unknown {u}"),
    }
}

enum VerificationStatus {
    Success,
    Disabled,
    Failed(String),
}

impl fmt::Display for VerificationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            VerificationStatus::Success => "success".to_string(),
            VerificationStatus::Disabled => "-".to_string(),
            VerificationStatus::Failed(err) => format!("failed - {}", err),
        };
        write!(f, "{}", s)
    }
}

fn format_audit_response(
    long: bool,
    signature: &SignatureResponse,
    signature_verification_status: &VerificationStatus,
    proof_verification_status: &VerificationStatus,
) -> Result<String> {
    if !long {
        return match (signature_verification_status, proof_verification_status) {
            (_, VerificationStatus::Disabled) => Ok(signature_verification_status.to_string()),
            (VerificationStatus::Failed(_), _) => Ok(signature_verification_status.to_string()),
            (_, _) => Ok(proof_verification_status.to_string()),
        };
    }

    let format = time::format_description::parse("[year]-[month]-[day]T[hour]:[minute]:[second]Z")?;
    let formatted_timestamp =
        time::OffsetDateTime::from_unix_timestamp((signature.timestamp() / 1000) as i64)?
            .format(&format)?;

    return Ok([
        "Namespace",
        format!(
            "  {: <22}: {namespace}",
            "Name".bold(),
            namespace = signature.namespace()
        )
        .as_str(),
        format!(
            "  {: <22}: {version}",
            "Ciphersuite".bold(),
            version = format_ciphersuite(signature.version())
        )
        .as_str(),
        format!("\nSignature ({timestamp})", timestamp = formatted_timestamp).as_str(),
        format!(
            "  {: <22}: {epoch}",
            "Epoch height".bold(),
            epoch = signature.epoch()
        )
        .as_str(),
        format!(
            "  {: <22}: {digest}",
            "Epoch digest".bold(),
            digest = hex::encode(signature.digest())
        )
        .as_str(),
        format!(
            "  {: <22}: {signature}",
            "Signature".bold(),
            signature = hex::encode(signature.signature())
        )
        .as_str(),
        format!(
            "  {: <22}: {status}",
            "Signature verification".bold(),
            status = signature_verification_status
        )
        .as_str(),
        format!(
            "  {: <22}: {status}",
            "Proof verification".bold(),
            status = proof_verification_status
        )
        .as_str(),
    ]
    .join("\n"));
}

pub async fn audit(
    namespace: &str,
    remote_url: &str,
    long: bool,
    verify: bool,
    verifying_key: Option<&str>,
    epoch: Option<&Epoch>,
) -> Result<String> {
    let client = PlexiClient::new(Url::parse(remote_url)?, None, Some(APP_USER_AGENT))?;
    let epoch = match epoch {
        Some(epoch) => epoch,
        None => {
            let Some(last_verified_epoch) = client.last_verified_epoch(namespace).await? else {
                return Err(anyhow!(
                    "namespace {namespace} does not have a latest epoch. Please specify one"
                ));
            };
            &last_verified_epoch.epoch()
        }
    };
    let Some(signature) = client.signature(namespace, epoch).await? else {
        return Err(anyhow!(
            "Signature not found for {namespace} at epoch {epoch}"
        ));
    };

    // no verification requested, we can stop here
    if !verify {
        return format_audit_response(
            long,
            &signature,
            &VerificationStatus::Disabled,
            &VerificationStatus::Disabled,
        );
    }

    // verify the signature against the log signature
    let config = client.auditor_config().await?;
    let verifying_key = match verifying_key {
        Some(key) => key,
        None => {
            let Some(key_id) = signature.key_id() else {
                return format_audit_response(
                    long,
                    &signature,
                    &VerificationStatus::Failed(
                        "don't want to implement random key validation".to_string(),
                    ),
                    &VerificationStatus::Disabled,
                );
            };
            let Some(key) = config
                .keys()
                .iter()
                .find(|key_info| key_info.key_id() == key_id)
            else {
                return format_audit_response(
                    long,
                    &signature,
                    &VerificationStatus::Failed(
                        "auditor does not have key with key_id".to_string(),
                    ),
                    &VerificationStatus::Disabled,
                );
            };

            key.public_key().as_str()
        }
    };

    let Ok(verifying_key) = hex::decode(verifying_key) else {
        return format_audit_response(
            long,
            &signature,
            &VerificationStatus::Failed("auditor key is not valid hex".to_string()),
            &VerificationStatus::Disabled,
        );
    };

    if signature.verify(&verifying_key).is_err() {
        return format_audit_response(
            long,
            &signature,
            &VerificationStatus::Failed(
                "signature does not verify for the auditor key".to_string(),
            ),
            &VerificationStatus::Disabled,
        );
    }

    // then download the proof and verify it
    if log_enabled!(log::Level::Error) {
        eprintln!("Audit proof verification enabled. It can take a few seconds");
    }

    let dots_handle = print_dots();

    // given Cloudflare does not expose the proof at the time of writing, uses the log directory and assume it's formatted like what WhatsApp provides
    let Some(namespace_info) = client.namespace(namespace).await? else {
        return format_audit_response(
            long,
            &signature,
            &VerificationStatus::Success,
            &VerificationStatus::Failed(format!("namespace {namespace} does not exist")),
        );
    };
    // if the namespace does not have a log directory, it means it does not provide proofs
    let Some(log_directory) = namespace_info.log_directory() else {
        return format_audit_response(
            long,
            &signature,
            &VerificationStatus::Success,
            &VerificationStatus::Disabled,
        );
    };

    // TODO: support namespace in the initialisation phase
    let Some(root) = namespace_info.root() else {
        return format_audit_response(
            long,
            &signature,
            &VerificationStatus::Success,
            &VerificationStatus::Failed(format!("namespace {namespace} does not have a root")),
        );
    };

    // First check if the epoch is the root or before root
    let (root_epoch, root_digest) = {
        let root_parts: Vec<&str> = root.split("/").collect();
        if root_parts.len() != 2 {
            return format_audit_response(
                long,
                &signature,
                &VerificationStatus::Success,
                &VerificationStatus::Failed(format!("namespace {namespace} has an invalid root")),
            );
        }
        let epoch: Epoch = root_parts[0].parse()?;
        let digest = hex::decode(root_parts[1])?;
        (epoch, digest)
    };

    if *signature.epoch() < root_epoch {
        return format_audit_response(
            long,
            &signature,
            &VerificationStatus::Success,
            &VerificationStatus::Failed("epoch cannot be before root".to_string()),
        );
    }

    if *signature.epoch() == root_epoch {
        if signature.digest() == root_digest {
            return format_audit_response(
                long,
                &signature,
                &VerificationStatus::Success,
                &VerificationStatus::Success,
            );
        } else {
            return format_audit_response(
                long,
                &signature,
                &VerificationStatus::Success,
                &VerificationStatus::Failed(
                    "epoch is at root height but does not match root digest".to_string(),
                ),
            );
        }
    }

    let previous_signature = client
        .signature(namespace, &(*signature.epoch() - 1))
        .await?
        .expect("Epoch is not the root, there should be a previous signature");

    let Ok(current_hash) = signature.digest().try_into() else {
        return format_audit_response(
            long,
            &signature,
            &VerificationStatus::Success,
            &VerificationStatus::Failed("digest length invalid".to_string()),
        );
    };

    let Ok(previous_hash) = previous_signature.digest().try_into() else {
        return format_audit_response(
            long,
            &signature,
            &VerificationStatus::Success,
            &VerificationStatus::Failed("digest length invalid".to_string()),
        );
    };

    let blob = AuditBlobName {
        epoch: signature.epoch().into(),
        previous_hash,
        current_hash,
    };
    let Some(raw_proof) = client.proof(&blob, Some(log_directory)).await? else {
        return format_audit_response(
            long,
            &signature,
            &VerificationStatus::Success,
            &VerificationStatus::Failed("cannot retrieve audit proof".to_string()),
        );
    };

    let verification = auditor::verify_raw_proof(&blob, &raw_proof).await;

    if log_enabled!(log::Level::Error) {
        eprintln!();
    }
    dots_handle.abort();

    if let Err(e) = verification {
        return format_audit_response(
            long,
            &signature,
            &VerificationStatus::Success,
            &VerificationStatus::Failed(e.to_string()),
        );
    }
    format_audit_response(
        long,
        &signature,
        &VerificationStatus::Success,
        &VerificationStatus::Success,
    )
}

pub async fn audit_local(
    verifying_key: Option<&str>,
    long: bool,
    verify: bool,
    proof_path: Option<PathBuf>,
    input: Option<PathBuf>,
) -> Result<String> {
    let src = file_or_stdin(input)?;
    let signature: SignatureResponse = serde_json::from_reader(src)?;

    // no verification requested, we can stop here
    if !verify {
        return format_audit_response(
            long,
            &signature,
            &VerificationStatus::Disabled,
            &VerificationStatus::Disabled,
        );
    }

    // verify the signature against the log signature
    let verifying_key = match verifying_key {
        Some(key) => key,
        None => {
            return format_audit_response(
                long,
                &signature,
                &VerificationStatus::Failed("auditor does not have key with key_id".to_string()),
                &VerificationStatus::Disabled,
            );
        }
    };

    let Ok(verifying_key) = hex::decode(verifying_key) else {
        return format_audit_response(
            long,
            &signature,
            &VerificationStatus::Failed("auditor key is not valid hex".to_string()),
            &VerificationStatus::Disabled,
        );
    };

    if signature.verify(&verifying_key).is_err() {
        return format_audit_response(
            long,
            &signature,
            &VerificationStatus::Failed(
                "signature does not verify for the auditor key".to_string(),
            ),
            &VerificationStatus::Disabled,
        );
    }

    let Some(proof_path) = proof_path else {
        return format_audit_response(
            long,
            &signature,
            &VerificationStatus::Success,
            &VerificationStatus::Disabled,
        );
    };

    let mut src = fs::File::open(proof_path).context("cannot read input file")?;

    let mut raw_proof = vec![];
    if let Err(e) = src.read_to_end(&mut raw_proof) {
        return format_audit_response(
            long,
            &signature,
            &VerificationStatus::Success,
            &VerificationStatus::Failed(e.to_string()),
        );
    };
    let raw_proof = raw_proof;
    let blob = AuditBlobName {
        epoch: signature.epoch().into(),
        previous_hash: auditor::compute_start_root_hash(&raw_proof).await?,
        current_hash: signature.digest().as_slice().try_into()?,
    };

    if log_enabled!(log::Level::Error) {
        eprintln!("Audit proof verification enabled. It can take a few seconds");
    }
    let dots_handle = print_dots();

    let verification = auditor::verify_raw_proof(&blob, &raw_proof).await;

    if log_enabled!(log::Level::Error) {
        eprintln!();
    }
    dots_handle.abort();

    if let Err(e) = verification {
        return format_audit_response(
            long,
            &signature,
            &VerificationStatus::Success,
            &VerificationStatus::Failed(e.to_string()),
        );
    }
    format_audit_response(
        long,
        &signature,
        &VerificationStatus::Success,
        &VerificationStatus::Success,
    )
}

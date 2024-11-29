use std::path::PathBuf;

use clap::{Parser, Subcommand};
use plexi_core::Epoch;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    #[clap(flatten)]
    pub verbose: clap_verbosity_flag::Verbosity,
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Information about a given epoch. By default, it retrieves and validates its audit proof
    #[command(verbatim_doc_comment)]
    Audit {
        /// URL of the auditor
        #[arg(short, long, env = "PLEXI_REMOTE_URL")]
        remote_url: String,
        /// Namespace ID
        #[arg(short, long, env = "PLEXI_NAMESPACE")]
        namespace: String,
        /// Ed25519 public key in hex format.
        #[arg(long, env = "PLEXI_VERIFYING_KEY")]
        verifying_key: Option<String>,
        /// Height of the epoch to verify. If not set, the latest epoch is verified.
        #[arg(long)]
        epoch: Option<Epoch>,
        /// Enable detailed output
        #[arg(short, long, default_value_t = false, group = "format")]
        long: bool,
        /// Disable signature and proof validation
        #[arg(long, default_value_t = false, env = "PLEXI_VERIFICATION_DISABLED")]
        no_verify: bool,
    },
    /// List all namespaces
    #[command(verbatim_doc_comment)]
    Ls {
        /// URL of the auditor
        #[arg(short, long, env = "PLEXI_REMOTE_URL")]
        remote_url: String,
        /// Namespace ID
        #[arg(short, long, env = "PLEXI_NAMESPACE")]
        namespace: Option<String>,
        /// Enable detailed output
        #[arg(short, long, default_value_t = false, group = "format")]
        long: bool,
    },
    #[command(verbatim_doc_comment)]
    LocalAudit {
        /// Ed25519 public key in hex format.
        #[arg(long, env = "PLEXI_VERIFYING_KEY")]
        verifying_key: Option<String>,
        /// Enable detailed output
        #[arg(short, long, default_value_t = false, group = "format")]
        long: bool,
        /// Disable signature and proof validation
        #[arg(long, default_value_t = false, env = "PLEXI_VERIFICATION_DISABLED")]
        no_verify: bool,
        /// Path to a file containing an epoch consistency proof
        /// Format is still ad-hoc, based on AKD
        #[arg(long, env = "PLEXI_PROOF_PATH")]
        proof_path: Option<PathBuf>,
        /// Path to a file containing an epoch to verify
        /// Format is { ciphersuite, namespace, timestamp, epoch, digest, signature }
        signature_path_or_stdin: Option<PathBuf>,
    },
}

#[allow(dead_code)]
pub fn build() -> Cli {
    Cli::parse()
}

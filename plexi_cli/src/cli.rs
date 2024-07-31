use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// 1. First interaction
///    plexi verify --publickey <publickey> --signature <signature> --message <message>
/// 2. TODOs
/// - plexi report
/// - plexi sign

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
    #[command(verbatim_doc_comment)]
    Verify {
        /// Namespace ID
        #[arg(short, long)]
        namespace: String,
        /// Ed25519 public key in hex format.
        #[arg(long)]
        publickey: String,
        /// Path to a file to read from.
        input: Option<PathBuf>,
    },
    #[command(verbatim_doc_comment)]
    Sign {
        /// Namespace ID
        #[arg(short, long)]
        namespace: String,
        /// Ed25519 signing key in hex format.
        #[arg(long)]
        signingkey: String,
        /// Write the result to the file at path OUTPUT.
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Path to a file to read from.
        input: Option<PathBuf>,
    },
}

#[allow(dead_code)]
pub fn build() -> Cli {
    Cli::parse()
}

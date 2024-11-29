use std::process;

mod cli;
mod cmd;
mod print;

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    let cli = cli::build();

    env_logger::Builder::new()
        .filter_level(cli.verbose.log_level_filter())
        .init();

    let output = match cli.command {
        cli::Commands::Ls {
            long,
            namespace,
            remote_url,
        } => cmd::ls(&remote_url, namespace.as_deref(), long).await,
        cli::Commands::Audit {
            epoch,
            namespace,
            remote_url,
            long,
            no_verify,
            verifying_key,
        } => {
            cmd::audit(
                &namespace,
                &remote_url,
                long,
                !no_verify,
                verifying_key.as_deref(),
                epoch.as_ref(),
            )
            .await
        }
        cli::Commands::LocalAudit {
            verifying_key,
            long,
            no_verify,
            proof_path,
            signature_path_or_stdin,
        } => {
            cmd::audit_local(
                verifying_key.as_deref(),
                long,
                !no_verify,
                proof_path,
                signature_path_or_stdin,
            )
            .await
        }
    };

    match output {
        Ok(result) => {
            if !result.is_empty() {
                println!("{result}")
            }
        }
        Err(err) => {
            eprintln!("error: {err}");
            process::exit(1)
        }
    };
    Ok(())
}

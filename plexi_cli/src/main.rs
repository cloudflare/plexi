use std::process;

mod cli;
mod cmd;

fn main() {
    let cli = cli::build();

    env_logger::Builder::new()
        .filter_level(cli.verbose.log_level_filter())
        .init();

    let output = match cli.command {
        cli::Commands::Verify { publickey, input } => cmd::verify(&publickey, input),
        cli::Commands::Sign {
            signingkey,
            output,
            input,
        } => cmd::sign(&signingkey, output, input),
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
    }
}

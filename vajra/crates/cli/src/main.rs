mod args;
mod runner;
mod output;

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::{fmt, EnvFilter};

use args::{Cli, Commands};
use runner::run_scan;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_logging(cli.verbose);

    match cli.command {
        Commands::Scan {
            targets,
            ports,
            concurrency,
            rate_limit,
            timeout,
            banner_timeout,
            output_format,
            scan_type,
            preset,
        } => {
            run_scan(
                targets,
                ports,
                concurrency,
                rate_limit,
                timeout,
                banner_timeout,
                output_format,
                preset,
                Some(scan_type),
            )
            .await?;
        }
    }

    Ok(())
}

fn init_logging(verbose: u8) {
    let log_level = match verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(log_level));

    fmt()
        .with_env_filter(filter)
        .compact()
        .init();
}

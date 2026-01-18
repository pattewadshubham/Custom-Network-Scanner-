use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "vajra")]
#[command(version = "0.1.0")]
#[command(about = "A modular vulnerability scanner", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Increase verbosity (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,
}

#[derive(Subcommand)]
pub enum Commands {
    Scan {
        /// Targets (IP or hostname). Example: 127.0.0.1 or example.com
        #[arg(short = 't', long, required = true)]
        targets: String,

        /// Ports to scan. Examples: 80,443 or 1-1024 or 22,80-90
        #[arg(short, long, default_value = "80")]
        ports: String,

    /// Max concurrent workers
    #[arg(short, long, default_value = "500")]
    concurrency: usize,

    /// Rate limit (requests per second)
    #[arg(short = 'r', long, default_value = "2000")]
    rate_limit: u64,

    /// Timeout in milliseconds
    #[arg(long, default_value = "1000")]
    timeout: u64,

    /// Banner grab timeout in milliseconds (controls how long we wait for service banners)
    #[arg(long, default_value = "300")]
    banner_timeout: u64,

        /// Output format: text, json, csv
        #[arg(short, long, default_value = "text")]
        output_format: String,

    /// Preset: fast, balanced, accurate, stealth
    #[arg(long, default_value = "balanced", value_parser = ["fast","balanced","accurate","stealth"])]
    preset: String,

        /// Scanner type to use for this job: "tcp" (connect) or "syn" (SYN scan)
        #[arg(long, default_value = "tcp", value_parser = ["tcp", "syn"])]
        scan_type: String,
    },
}

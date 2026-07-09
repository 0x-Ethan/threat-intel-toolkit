use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::info;

mod modules;

/// threat-intel-toolkit (tit)
/// Passive threat intelligence and OSINT research toolkit.
/// All operations use public, passive data sources only.
#[derive(Parser)]
#[command(
    name = "tit",
    version,
    author,
    about = "Passive threat intelligence & OSINT research toolkit",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Output format: json | text
    #[arg(short, long, default_value = "text", global = true)]
    output: String,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Passive DNS enumeration via certificate transparency and public resolvers
    Dns {
        /// Target domain
        #[arg(short, long)]
        target: String,

        /// Maximum results to return
        #[arg(short, long, default_value = "100")]
        limit: usize,
    },

    /// Certificate transparency log search
    Ct {
        /// Target domain
        #[arg(short, long)]
        target: String,

        /// Include expired certificates
        #[arg(long, default_value = "false")]
        include_expired: bool,
    },

    /// MITRE ATT&CK technique mapper for observed TTPs
    Atk {
        /// Technique ID (e.g. T1590.001)
        #[arg(short, long)]
        technique: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize structured logging
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(if cli.verbose {
            "threat_intel_toolkit=debug"
        } else {
            "threat_intel_toolkit=info"
        })
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    match cli.command {
        Commands::Dns { target, limit } => {
            info!("Starting passive DNS enumeration for: {}", target);
            modules::dns::run(&target, limit, &cli.output).await?;
        }
        Commands::Ct {
            target,
            include_expired,
        } => {
            info!("Searching certificate transparency logs for: {}", target);
            modules::ct::run(&target, include_expired, &cli.output).await?;
        }
        Commands::Atk { technique } => {
            info!("Mapping MITRE ATT&CK technique: {}", technique);
            modules::atk::run(&technique, &cli.output).await?;
        }
    }

    Ok(())
}

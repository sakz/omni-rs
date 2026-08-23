use clap::Parser;
use clap::Subcommand;

#[derive(Parser, Debug)]
#[command(
    name = "omni-rs-bin",
    about = "omni-rs v2 framework runtime",
    version = None,
    disable_version_flag = true
)]
pub struct Cli {
    #[arg(
        short,
        long,
        help = "Config file path (.json or .toml). Used when no subcommand is given"
    )]
    pub config: Option<String>,

    #[arg(long, help = "Validate config and capability matrix, then exit")]
    pub check_config: bool,

    #[command(subcommand)]
    pub command: Option<Command>,
}

impl Cli {
    pub fn effective(&self) -> (Option<String>, bool) {
        match &self.command {
            Some(Command::Server {
                config,
                check_config,
            }) => (
                config.clone().or(self.config.clone()),
                *check_config || self.check_config,
            ),
            _ => (self.config.clone(), self.check_config),
        }
    }
}

#[derive(Subcommand, Debug)]
pub enum Command {
    #[command(about = "Start the server (v1-compatible alias for the default behaviour)")]
    Server {
        #[arg(short, long, help = "Config file path (.json or .toml)")]
        config: Option<String>,
        #[arg(long, help = "Validate config and capability matrix, then exit")]
        check_config: bool,
    },
    #[command(about = "Print CLI version")]
    Version,
}

#[derive(Debug, Clone)]
pub struct EffectiveArgs {
    pub config: Option<String>,
}

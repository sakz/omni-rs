mod bootstrap;
mod cli;
mod cmd;

use clap::Parser;

fn main() {
    let args = cli::Cli::parse();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");
    let code = rt.block_on(async move { dispatch(args).await });
    std::process::exit(code);
}

async fn dispatch(args: cli::Cli) -> i32 {
    omni_log::init(omni_log::Format::Omni);
    match &args.command {
        Some(cli::Command::Version) => {
            println!("omni-cli {}", env!("CARGO_PKG_VERSION"));
            0
        }
        _ => {
            let (config, check_config) = args.effective();
            let eff = cli::EffectiveArgs { config };
            if check_config {
                cmd::check_config::run(&eff).await
            } else {
                cmd::run::run(&eff).await
            }
        }
    }
}

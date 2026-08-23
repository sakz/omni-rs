use crate::bootstrap::runtime::{assemble, bootstrap_log_start};
use crate::cli::EffectiveArgs;

pub async fn run(args: &EffectiveArgs) -> i32 {
    bootstrap_log_start();
    match assemble(args).await {
        Ok(_rt) => {
            tracing::info!(target: "reconcile.init", "initial reconcile completed");
            println!("config check passed");
            0
        }
        Err(e) => {
            tracing::error!(target: "reconcile.init", error = e.as_str(), "initial reconcile failed");
            tracing::error!(target: "omni.start", fatal = true, error = e.as_str(), "core initialization failed");
            eprintln!("runtime assembly failed: {}", e);
            1
        }
    }
}

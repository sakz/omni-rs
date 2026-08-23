use crate::bootstrap::runtime;
use crate::cli::EffectiveArgs;

pub async fn run(args: &EffectiveArgs) -> i32 {
    runtime::run_server(args).await
}

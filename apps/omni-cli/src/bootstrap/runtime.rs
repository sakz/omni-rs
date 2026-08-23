use crate::cli::EffectiveArgs;
use omni_config::wire::RuntimeConfigWire;

pub async fn assemble(args: &EffectiveArgs) -> Result<omni_core::runtime::core::CoreRuntime, String> {
    let wire: RuntimeConfigWire = match &args.config {
        Some(path) => omni_config::read_config(path).map_err(|e| e.to_string())?,
        None => RuntimeConfigWire::default(),
    };

    let backend_override = std::env::var("omni_backend").ok();
    let backend = omni_core::dataplane::select_backend(backend_override);
    tracing::info!(target: "runtime.backend", "{}", backend.as_str());

    omni_core::runtime::core::CoreRuntime::initialize(&wire)
        .await
        .map_err(|e| e.to_string())
}

pub async fn run_server(args: &EffectiveArgs) -> i32 {
    bootstrap_log_start();

    match assemble(args).await {
        Ok(rt) => {
            tracing::info!(target: "reconcile.init", "initial reconcile completed");
            if rt.plans.is_empty() {
                0
            } else {
                match rt.serve().await {
                    Ok(()) => 0,
                    Err(e) => fatal(&e.to_string()),
                }
            }
        }
        Err(e) => fatal(&e),
    }
}

fn fatal(err: &str) -> i32 {
    tracing::error!(target: "reconcile.init", error = err, "initial reconcile failed");
    tracing::error!(target: "omni.start", fatal = true, error = err, "core initialization failed");
    eprintln!("runtime assembly failed: {}", err);
    1
}

pub fn bootstrap_log_start() {
    tracing::info!(
        target: "omni.start",
        version = env!("CARGO_PKG_VERSION"),
        "initializing"
    );
    #[cfg(feature = "mimalloc")]
    tracing::info!(target: "omni.start", "mimalloc allocator enabled");
    if cfg!(target_os = "linux") {
        tracing::info!(
            target: "omni.start",
            "io_uring backend available (Linux kernel 5.1+, NO_IOWAIT requires 6.15+)"
        );
    }
}

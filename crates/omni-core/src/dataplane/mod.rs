use omni_config::model::Backend;

#[tracing::instrument]
pub fn iouring_available() -> bool {
    cfg!(target_os = "linux")
}

pub fn select_backend(env_override: Option<String>) -> Backend {
    let default = if cfg!(target_os = "linux") {
        Backend::Iouring
    } else {
        Backend::Tokio
    };
    match env_override.as_deref() {
        None => default,
        Some(s) => match s {
            "iouring" if cfg!(target_os = "linux") => Backend::Iouring,
            "epoll" if cfg!(target_os = "linux") => Backend::Epoll,
            "tokio" => Backend::Tokio,
            _ => {
                tracing::warn!("runtime.backend: ignoring invalid omni_backend override");
                default
            }
        },
    }
}

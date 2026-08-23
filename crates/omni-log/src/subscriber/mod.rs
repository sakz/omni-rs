pub mod fmt_layer;

use crate::Format;
use std::io;
use tracing_subscriber::{filter, layer::SubscriberExt, util::SubscriberInitExt, Layer, Registry};

pub fn init(format: Format) {
    let filter = filter::EnvFilter::try_from_env("OMNI_LOG")
        .unwrap_or_else(|_| filter::EnvFilter::new("info"));
    match format {
        Format::Json => {
            let layer = tracing_subscriber::fmt::layer()
                .json()
                .with_timer(fmt_layer::OmniTimer)
                .with_writer(io::stderr)
                .with_filter(filter);
            Registry::default().with(layer).init();
        }
        Format::Omni => {
            let layer = tracing_subscriber::fmt::layer()
                .event_format(fmt_layer::OmniFormatter)
                .with_writer(io::stderr)
                .with_filter(filter);
            Registry::default().with(layer).init();
        }
    }
}

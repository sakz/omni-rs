use std::sync::Arc;

pub mod composer;
pub mod executor;
pub mod inspector;

#[derive(Clone)]
pub struct PipelineShared {
    pub inbound_tag: String,
    pub counters: Arc<crate::observability::Counters>,
    pub online: Arc<crate::observability::online_tracker::OnlineTracker>,
    pub router: Arc<crate::runtime::assembly::outbound_artifacts::Router>,
    pub dialer: Arc<omni_transport::dial::Dialer>,
}

pub struct ConnMeta {
    pub user: Option<String>,
}

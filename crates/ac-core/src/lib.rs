//! Agent Control core library.
//!
//! Exposes the event store, state machine, session manager,
//! adapter contract, control API server, account manager,
//! and project registry.

pub mod account_manager;
pub mod adapter;
pub mod agy_auth;
pub mod agy_discovery;
pub mod agy_launch;
pub mod config;
pub mod cost;
pub mod cost_store;
pub mod credentials;
pub mod doctor;
pub mod event_store;
pub mod interaction_hub;
pub mod ipc;
pub mod metrics;
pub mod notifications;
pub mod policy_engine;
pub mod project_registry;
pub mod queue_store;
pub mod sandbox;
pub mod session;
pub mod settings;
pub mod template_manager;
pub mod theme;
pub mod types;
pub mod ws;

pub use cost::{calculate_cost, TokenUsage};
pub use cost_store::CostStore;
pub use notifications::{
    ChannelTestResult, NotificationDispatcher, NotificationHandle, NotificationMetrics,
    NotificationStatusReport, NotificationTestResult,
};
pub use queue_store::QueueStore;
pub use template_manager::{TemplateManager, TemplateManagerHandle, TemplateStore};


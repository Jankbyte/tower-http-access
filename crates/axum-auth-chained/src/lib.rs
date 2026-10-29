//! Chain-based authentication middleware for Axum.

pub mod authentication;
pub mod authorization;
mod security_builder;

pub use security_builder::{AuthorizationCustomizer, SecurityLayerBuilder, SecurityServiceBuilder};

#[cfg(feature = "basic_auth")]
pub mod basic;

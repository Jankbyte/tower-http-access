//! Chain-based authentication middleware for Axum.

pub mod authentication;
pub mod authorization;
mod combined;
#[cfg(feature = "request_matcher")]
pub use authorization::request_matcher;
pub use combined::{SecurityLayer, SecurityService};

#[cfg(feature = "basic_auth")]
pub mod basic;

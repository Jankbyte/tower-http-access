#![doc = include_str!("../README.md")]

pub mod authentication;
pub mod authorization;
mod combined;
mod response;
#[cfg(feature = "request_matcher")]
pub use authorization::request_matcher;
pub use combined::{SecurityLayer, SecurityService};
pub use response::{DefaultSecurityResponseAdapter, SecurityResponse, SecurityResponseAdapter};

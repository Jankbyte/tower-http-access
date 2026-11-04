#![doc = include_str!("../README.md")]

pub mod authentication;
pub mod authorization;
mod combined;
#[cfg(feature = "filter_chain")]
pub mod filter_chain;
#[cfg(feature = "request_matcher")]
pub mod request_matcher;
mod response;
pub use combined::{SecurityLayer, SecurityService};
#[cfg(feature = "filter_chain")]
pub use filter_chain::{SecurityChainLayer, SecurityChainService};
pub use response::{DefaultSecurityResponseAdapter, SecurityResponse, SecurityResponseAdapter};

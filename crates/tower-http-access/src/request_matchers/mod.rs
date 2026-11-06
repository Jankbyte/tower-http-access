//! Synchronous request matching for security chains and authorization rules.
//!
//! A matcher selects a chain or policy; it does not grant or deny access itself.
//! Patterns are compiled once and matching borrows request metadata.

mod any;
pub use any::AnyRequestMatcher;

mod core;
pub use core::RequestMatcher;

mod media_type;
pub use media_type::{InvalidMediaType, MediaTypeRequestMatcher};

mod or;
pub use or::OrRequestMatcher;

mod path_pattern;
pub use path_pattern::{InvalidRequestPattern, PathPatternRequestMatcher};

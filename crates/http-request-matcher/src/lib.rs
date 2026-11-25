#![doc = include_str!("../README.md")]

mod any;
mod core;
#[cfg(feature = "media_type")]
mod media_type;
mod or;
#[cfg(feature = "path")]
mod path_pattern;

pub use any::AnyRequestMatcher;
pub use core::RequestMatcher;
#[cfg(feature = "media_type")]
pub use media_type::{InvalidMediaType, MediaTypeRequestMatcher};
pub use or::OrRequestMatcher;
#[cfg(feature = "path")]
pub use path_pattern::{InvalidRequestPattern, PathPatternRequestMatcher};

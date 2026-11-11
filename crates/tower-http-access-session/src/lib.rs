#![doc = include_str!("../README.md")]

/// Authentication and login persistence using `tower-sessions`.
///
/// Available with the `tower_sessions` feature, enabled by default.
#[cfg(feature = "tower_sessions")]
pub mod tower_sessions;

#[cfg(feature = "browser_matcher")]
mod browser_matcher;
#[cfg(feature = "browser_matcher")]
pub use browser_matcher::BrowserRequestMatcher;

#[cfg(feature = "session_matcher")]
mod session_matcher;
#[cfg(feature = "session_matcher")]
pub use session_matcher::SessionCookieRequestMatcher;

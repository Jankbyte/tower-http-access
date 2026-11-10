#![doc = include_str!("../README.md")]

mod authenticator;
pub use authenticator::{
    InvalidLoginPagePath, SessionIdentityProvider, SessionRequestAuthenticator, initialize_session,
};

mod stored_identity;
pub use stored_identity::SessionStoredIdentity;

/// Form login middleware and configurable authentication handlers.
#[cfg(feature = "form_login_layer")]
pub mod form_login;

#[cfg(feature = "browser_matcher")]
mod browser_matcher;
#[cfg(feature = "browser_matcher")]
pub use browser_matcher::BrowserRequestMatcher;

#[cfg(feature = "session_matcher")]
mod session_matcher;
#[cfg(feature = "session_matcher")]
pub use session_matcher::SessionCookieRequestMatcher;

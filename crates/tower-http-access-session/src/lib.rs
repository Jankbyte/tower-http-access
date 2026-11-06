#![doc = include_str!("../README.md")]

mod authenticator;
pub use authenticator::{
    InvalidLoginPagePath, SessionIdentityProvider, SessionRequestAuthenticator, initialize_session,
};

mod stored_identity;
pub use stored_identity::SessionStoredIdentity;

#[cfg(feature = "browser_matcher")]
mod browser_matcher;
#[cfg(feature = "browser_matcher")]
pub use browser_matcher::BrowserRequestMatcher;

#[cfg(feature = "session_matcher")]
mod session_matcher;
#[cfg(feature = "session_matcher")]
pub use session_matcher::SessionCookieRequestMatcher;

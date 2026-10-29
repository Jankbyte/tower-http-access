//! Implementation of basic authenticator.
mod authenticator;
mod base64;
mod password;
mod user_detail;

pub use password::{
    AsyncPasswordHasher, AsyncPasswordVerifier, AsyncStringPasswordManager,
    PlainHashPasswordManager,
};

pub use authenticator::BasicRequestAuthenticator;
pub use user_detail::{InMemoryUserDetailService, UserDetail, UserDetailService};

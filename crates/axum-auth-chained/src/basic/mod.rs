//! Implementation of basic authenticator.
mod authenticator;
mod base64;
mod password;
mod user_detail;

pub use password::{
    AsyncPasswordError, AsyncPasswordHasher, AsyncPasswordVerifier, AsyncStringPasswordManager,
    PlainHashPasswordManager,
};

pub use authenticator::{
    BasicRequestAuthenticator, UsernamePasswordAuthenticationFuture,
    UsernamePasswordAuthenticationProvider,
};
pub use base64::BasicCredentials;
pub use user_detail::{
    Authority, InMemoryUserDetailService, UserDetail, UserDetailAuthenticationError,
    UserDetailAuthenticationProvider, UserDetailService,
};

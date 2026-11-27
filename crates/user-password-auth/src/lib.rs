#![doc = include_str!("../README.md")]

mod authentication;
mod credentials;
#[cfg(feature = "password")]
mod password;
#[cfg(feature = "user_details")]
mod user_detail;

pub use authentication::UsernamePasswordAuthenticationProvider;
pub use credentials::Credentials;

#[cfg(feature = "password")]
pub use password::{
    AsyncPasswordError, AsyncPasswordHasher, AsyncPasswordVerifier, AsyncStringPasswordManager,
    PasswordQueuePolicy, PlainHashPasswordManager,
};
#[cfg(feature = "user_details")]
pub use user_detail::{
    Authority, InMemoryUserDetailService, UserDetail, UserDetailAuthenticationError,
    UserDetailAuthenticationProvider, UserDetailService, UserLoadingError,
};

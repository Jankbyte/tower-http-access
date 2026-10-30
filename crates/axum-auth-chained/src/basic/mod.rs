//! Implementation of basic authenticator.
mod authenticator;
pub mod authorization;
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
pub use authorization::{
    HasAuthorities, InvalidRequestPattern, PendingRuleBuilder, RequestAuthorizationBuilder,
    RequestAuthorizationProvider, RequestContext, request_context_mapper,
};
pub use base64::BasicCredentials;
pub use user_detail::{
    Authority, InMemoryUserDetailService, UserDetail, UserDetailAuthenticationError,
    UserDetailAuthenticationProvider, UserDetailService,
};

use super::base64::extract_credentials;
use super::{AsyncPasswordVerifier, UserDetail, UserDetailService};
use crate::{
    authentication::{
        AuthenticationAttempt, AuthenticationErrorReason, AuthenticatorError, RequestAuthenticator,
    },
    authorization::AuthenticationEntryPoint,
};
use axum::{
    extract::Request,
    http::{StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
};
use std::{error::Error, future::Future, pin::Pin};

/// HTTP Basic authentication for Axum requests.
///
/// This authenticator implements the [`Basic` authentication scheme defined by RFC 7617](https://www.rfc-editor.org/rfc/rfc7617.html). Basic
/// credentials are only Base64-encoded, not encrypted, so applications must use HTTPS when sending
/// them over a network.
///
/// Authenticator based on two components:
///
/// * [`AsyncPasswordVerifier`] - compare raw password with hashed.
/// * [`UserDetailService`] - source with users.
///
/// # Behavior
///
/// When request is coming, authenticator check `Authorization` header, and if header is missed or does not start with `Basic`
/// schema - skip this request with [`AuthenticationAttempt::NotApplicable`] as result.
///
/// Otherwise, extract credentials, find user by his username and compare raw password with hashed.
/// A malformed Basic header, unknown user, or wrong password stops the authenticator chain and
/// returns `401 Unauthorized` with a `WWW-Authenticate: Basic` challenge. This follows the
/// [HTTP authentication requirements in RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.4). A missing header or a different authentication
/// scheme returns [`AuthenticationAttempt::NotApplicable`] so another authenticator can try the
/// request.
///
/// # Example
///
/// ```rust
/// use argon2::Argon2;
/// use axum_auth_chained::basic::{AsyncStringPasswordManager, InMemoryUserDetailService, UserDetail, BasicRequestAuthenticator};
/// use std::num::NonZeroUsize;
/// use tokio::runtime::Handle;
///
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() {
/// let manager: AsyncStringPasswordManager<Argon2> =
///     AsyncStringPasswordManager::new(Handle::current(), Argon2::default(), NonZeroUsize::new(2).unwrap());
///
/// let raw_users = vec![
///     UserDetail::new("alex", "alex123"),
///     UserDetail::new("max", "max123"),
/// ];
///
/// let user_detail_service = InMemoryUserDetailService::new((&manager, raw_users))
///     .await
///     .unwrap();
///
/// let basic_authenticator = BasicRequestAuthenticator::new(manager, user_detail_service);
/// # }
/// ```
///
#[derive(Clone)]
pub struct BasicRequestAuthenticator<V, U> {
    password_verifier: V,
    user_detail_service: U,
}

impl<V, U> BasicRequestAuthenticator<V, U> {
    /// Create new basic authenticator from password verifier and users store.
    pub fn new(password_verifier: V, user_detail_service: U) -> Self {
        Self {
            password_verifier,
            user_detail_service,
        }
    }
}

impl<V, U> RequestAuthenticator for BasicRequestAuthenticator<V, U>
where
    V: AsyncPasswordVerifier,
    U: UserDetailService,
{
    type Authentication = UserDetail;

    fn authenticate<'a>(
        &'a self,
        parts: &'a mut Parts,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        AuthenticationAttempt<Self::Authentication>,
                        AuthenticatorError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let Some(credentials) = extract_credentials(parts).map_err(|_| wrong_credentials())?
            else {
                return Ok(AuthenticationAttempt::NotApplicable);
            };
            let user = self
                .user_detail_service
                .load_user_by_name(&credentials.username)
                .await
                .map_err(internal_error)?;
            let Some(user) = user else {
                return Err(wrong_credentials());
            };
            let matches = self
                .password_verifier
                .matches(&credentials.password, &user.hashed_password)
                .await
                .map_err(internal_error)?;
            if !matches {
                return Err(wrong_credentials());
            }

            Ok(AuthenticationAttempt::Authenticated(user))
        })
    }
}

impl<V, U> AuthenticationEntryPoint for BasicRequestAuthenticator<V, U>
where
    V: Send + Sync + 'static,
    U: Send + Sync + 'static,
{
    fn commence(&self, _: Request) -> Response {
        basic_challenge()
    }
}

fn wrong_credentials() -> AuthenticatorError {
    AuthenticatorError::with_response(
        AuthenticationErrorReason::WrongCredentials,
        basic_challenge(),
    )
}

fn basic_challenge() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, r#"Basic realm="Realm""#)],
    )
        .into_response()
}

fn internal_error(error: impl Error + Send + Sync + 'static) -> AuthenticatorError {
    AuthenticatorError::new(AuthenticationErrorReason::Internal(Box::new(error)))
}

#[cfg(test)]
#[path = "authenticator_tests.rs"]
mod tests;

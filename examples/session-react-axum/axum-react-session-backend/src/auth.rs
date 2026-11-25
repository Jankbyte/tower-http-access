use crate::principal::Principal;
use axum::{
    Json, Router,
    body::Body,
    http::{Method, Request, StatusCode},
    response::IntoResponse,
    routing::{get, post, post_service},
};
use http_request_matcher::PathPatternRequestMatcher;
use std::convert::Infallible;
use tower::{Layer, service_fn};
use tower_http_access_core::authentication::Authenticated;
use tower_http_access_form_login::{DefaultFailureHandler, DefaultSuccessHandler, FormLoginLayer};
use tower_http_access_session::tower_sessions::SessionSetSuccessHandler;
use user_password_auth::{Authority, UserDetail, UsernamePasswordAuthenticationProvider};

pub(crate) const LOGIN_PATH: &str = "/v1/ui/auth/login";
pub(crate) const ME_PATH: &str = "/v1/ui/auth/me";
pub(crate) const LOGOUT_PATH: &str = "/v1/ui/auth/logout";

pub(crate) fn router<P>(
    session_auth_key: &str,
    provider: P,
) -> Result<Router, Box<dyn std::error::Error + Send + Sync>>
where
    P: UsernamePasswordAuthenticationProvider<
            Authentication = UserDetail,
            Error: Send + Sync + 'static,
        > + Clone
        + Send
        + Sync
        + 'static,
{
    let login = create_form_login_layer(session_auth_key, provider)?.layer(service_fn(
        |_: Request<Body>| async {
            // A POST on LOGIN_PATH is consumed by FormLoginLayer. Reaching this
            // service indicates a mismatch between the route and login matcher.
            Ok::<_, Infallible>(StatusCode::INTERNAL_SERVER_ERROR.into_response())
        },
    ));
    Ok(Router::new()
        .route(LOGIN_PATH, post_service(login))
        .route(LOGOUT_PATH, post(logout))
        .route(ME_PATH, get(current_user)))
}

type LoginLayer<P, R> = FormLoginLayer<
    P,
    PathPatternRequestMatcher,
    SessionSetSuccessHandler<R, DefaultSuccessHandler>,
    DefaultFailureHandler,
>;

fn create_form_login_layer<P>(
    session_auth_key: &str,
    provider: P,
) -> Result<
    LoginLayer<P, impl Fn(&UserDetail) -> UserDetail + Clone + Send + Sync + use<P>>,
    Box<dyn std::error::Error + Send + Sync>,
>
where
    P: UsernamePasswordAuthenticationProvider<
            Authentication = UserDetail,
            Error: Send + Sync + 'static,
        > + Clone,
{
    Ok(FormLoginLayer::new(provider)
        .request_matcher(PathPatternRequestMatcher::new(LOGIN_PATH)?.with_method(Method::POST))
        .remember_parameter("remember_me")
        .on_success(
            SessionSetSuccessHandler::new(|user: &UserDetail| user.clone(), DefaultSuccessHandler)
                .with_session_key(session_auth_key),
        )
        .on_failure(DefaultFailureHandler))
}

async fn logout(axum::Extension(session): axum::Extension<tower_sessions::Session>) -> StatusCode {
    match session.flush().await {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

#[derive(serde::Serialize)]
struct CurrentUser {
    username: String,
    authorities: Vec<Authority>,
}

async fn current_user(Authenticated(user): Authenticated<Principal>) -> Json<CurrentUser> {
    Json(CurrentUser {
        username: user.0.username,
        authorities: user.0.authorities,
    })
}

use axum::{
    Json, Router,
    body::Body,
    http::{Method, Request, StatusCode, header},
    response::IntoResponse,
    routing::{get, post_service},
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
    P: UsernamePasswordAuthenticationProvider<Authentication = UserDetail> + Clone,
{
    Ok(FormLoginLayer::new(provider)
        .request_matcher(PathPatternRequestMatcher::new(LOGIN_PATH)?.with_method(Method::POST))
        .on_success(
            SessionSetSuccessHandler::identity(DefaultSuccessHandler)
                .with_session_key(session_auth_key),
        )
        .on_failure(DefaultFailureHandler))
}

/// Browser authentication routes. Session, CSRF, and authorization layers run outside.
pub(crate) fn router<P>(
    session_auth_key: &str,
    provider: P,
) -> Result<Router, Box<dyn std::error::Error + Send + Sync>>
where
    P: UsernamePasswordAuthenticationProvider<Authentication = UserDetail> + Clone + 'static,
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
        .route(ME_PATH, get(current_user)))
}

/// Public identity returned to the SPA. Password hashes stay on the server.
#[derive(serde::Serialize)]
struct CurrentUser {
    username: String,
    authorities: Vec<Authority>,
}

async fn current_user(
    Authenticated(user): Authenticated<UserDetail>,
) -> impl axum::response::IntoResponse {
    (
        [(header::CACHE_CONTROL, "no-store")],
        Json(CurrentUser {
            username: user.username,
            authorities: user.authorities,
        }),
    )
}

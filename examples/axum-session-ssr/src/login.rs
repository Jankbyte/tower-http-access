use crate::SESSION_COOKIE_ID;
use crate::SessionIdentity;
use axum::http::Method;
use axum::{
    extract::{Extension, Query},
    response::{Html, Redirect},
};
use http_request_matcher::PathPatternRequestMatcher;
use tower_http_access_core::authentication::Authenticated;
use tower_http_access_form_login::{FormLoginLayer, RedirectFormLoginHandler};
use tower_http_access_session::csrf::CsrfToken;
use tower_http_access_session::tower_sessions::SessionSetSuccessHandler;
use user_password_auth::{UserDetail, UsernamePasswordAuthenticationProvider};

pub(crate) const LOGIN_PAGE_PATH: &str = "/auth/login";

#[derive(serde::Deserialize)]
pub(crate) struct LoginQuery {
    error: Option<String>,
}

pub(crate) async fn login_page(
    Extension(csrf): Extension<CsrfToken>,
    Query(query): Query<LoginQuery>,
    auth: Option<Authenticated<SessionIdentity>>,
) -> Result<Html<String>, Redirect> {
    if auth.is_some() {
        return Err(Redirect::permanent("/"));
    }
    let error = if query.error.as_deref() == Some("true") {
        "<p role=\"alert\">Invalid username or password.</p>"
    } else {
        ""
    };
    Ok(Html(format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Login</title></head>
<body>
    <h1>Login</h1>
    {error}
    <form method="post" action="{LOGIN_PAGE_PATH}">
        <input type="hidden" name="{csrf_name}" value="{csrf_value}">
        <label for="username">Username</label>
        <input id="username" name="username" autocomplete="username" required>
        <label for="password">Password</label>
        <input id="password" name="password" type="password" autocomplete="current-password" required>
        <button type="submit">Login</button>
    </form>
</body>
</html>"#,
        csrf_name = csrf.parameter_name,
        csrf_value = csrf.token,
    )))
}

type LoginLayer<P, R> = FormLoginLayer<
    P,
    PathPatternRequestMatcher,
    SessionSetSuccessHandler<R, RedirectFormLoginHandler>,
    RedirectFormLoginHandler,
>;

pub(crate) fn create_form_login_layer<P>(
    provider: P,
) -> Result<
    LoginLayer<P, impl Fn(&UserDetail) -> SessionIdentity + Clone + Send + Sync>,
    Box<dyn std::error::Error + Send + Sync>,
>
where
    P: UsernamePasswordAuthenticationProvider<Authentication = UserDetail> + Clone,
{
    let map_identity: fn(&UserDetail) -> SessionIdentity = |identity| SessionIdentity {
        username: identity.username.clone(),
    };
    Ok(FormLoginLayer::new(provider)
        .request_matcher(PathPatternRequestMatcher::new(LOGIN_PAGE_PATH)?.with_method(Method::POST))
        .on_success(
            SessionSetSuccessHandler::new(map_identity, RedirectFormLoginHandler::new("/")?)
                .with_session_key(SESSION_COOKIE_ID),
        )
        .on_failure(RedirectFormLoginHandler::new(format!(
            "{LOGIN_PAGE_PATH}?error=true"
        ))?))
}

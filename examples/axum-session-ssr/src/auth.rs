use crate::SessionIdentity;
use axum::{
    extract::Extension,
    http::StatusCode,
    response::{Html, Redirect},
};
use tower_http_access_core::authentication::Authenticated;
use tower_http_access_session::csrf::CsrfToken;
use tower_sessions::Session;

pub(crate) const LOGOUT_PAGE_PATH: &str = "/auth/logout";
pub(crate) const ME_PAGE_PATH: &str = "/me";

pub(crate) async fn logout(Extension(session): Extension<Session>) -> Result<Redirect, StatusCode> {
    session
        .flush()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Redirect::to(crate::login::LOGIN_PAGE_PATH))
}

pub async fn get_authenticated(
    Authenticated(data): Authenticated<SessionIdentity>,
    Extension(csrf): Extension<CsrfToken>,
) -> Html<String> {
    Html(format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Me</title></head>
<body>
    <h1>Authenticated</h1>
    <p>Username: {username}</p>
    <form method="post" action="{LOGOUT_PAGE_PATH}">
        <input type="hidden" name="{csrf_name}" value="{csrf_value}">
        <button type="submit">Logout</button>
    </form>
</body>
</html>"#,
        username = data.username,
        csrf_name = csrf.parameter_name,
        csrf_value = csrf.token,
    ))
}

use super::auth::ME_PAGE_PATH;
use super::login::LOGIN_PAGE_PATH;
use crate::SessionIdentity;
use axum::response::Html;
use tower_http_access_core::authentication::Authenticated;

pub(crate) const MAIN_PAGE_PATH: &str = "/";

pub(crate) async fn main_page(auth: Option<Authenticated<SessionIdentity>>) -> Html<String> {
    let authenticated_text = if let Some(Authenticated(user)) = auth {
        user.username
    } else {
        "anonymous".to_owned()
    };
    Html(format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Main</title></head>
<body>
    <h1>Main page</h1>
    <p>Authenticated as {name}</p>
    <ul>
        <li><a href="{LOGIN_PAGE_PATH}">Login page</a></li>
        <li><a href="{ME_PAGE_PATH}">User space</a></li>
    </ul>
</body>
</html>"#,
        name = authenticated_text
    ))
}

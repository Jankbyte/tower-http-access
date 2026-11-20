use super::*;
use crate::csrf::CsrfLayer;
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::Extension,
    routing::get,
};
use http::{Request, StatusCode, header};
use std::sync::Arc;
use tower::ServiceExt;
use tower_cookies::CookieManagerLayer;
use tower_sessions::{MemoryStore, SessionManagerLayer};

type Repository = Arc<dyn CsrfTokenRepository<Error = CsrfRepositoryError>>;

fn session_parts() -> Parts {
    let (mut parts, _) = Request::new(()).into_parts();
    parts
        .extensions
        .insert(Session::new(None, Arc::new(MemoryStore::default()), None));
    parts
}

#[tokio::test]
async fn session_repository_scopes_persists_and_removes_tokens() {
    let repo = HttpSessionCsrfTokenRepository::new()
        .with_session_key("custom_csrf")
        .with_header_name(HeaderName::from_static("x-custom-csrf"))
        .with_parameter_name("custom_csrf");
    let parts = session_parts();
    assert!(repo.load_token(&parts).await.unwrap().is_none());
    assert!(parts.extensions.get::<Session>().unwrap().is_empty().await);
    let first = repo.generate_token().unwrap();
    let second = repo.generate_token().unwrap();
    assert_eq!(first.token.len(), 64);
    assert_ne!(first.token, second.token);
    repo.save_token(&parts, Some(&first)).await.unwrap();
    let loaded = repo.load_token(&parts).await.unwrap().unwrap();
    assert_eq!(loaded.token, first.token);
    assert_eq!(loaded.header_name, "x-custom-csrf");
    assert_eq!(loaded.parameter_name, "custom_csrf");
    assert!(repo.load_token(&session_parts()).await.unwrap().is_none());
    assert!(
        HttpSessionCsrfTokenRepository::new()
            .load_token(&parts)
            .await
            .unwrap()
            .is_none()
    );

    // Confirm that persistence uses the configured session key.
    let session = parts.extensions.get::<Session>().unwrap();
    session.save().await.unwrap();
    assert_eq!(
        session.get::<String>("custom_csrf").await.unwrap().unwrap(),
        first.token
    );
    repo.save_token(&parts, Some(&second)).await.unwrap();
    assert_eq!(
        repo.load_token(&parts).await.unwrap().unwrap().token,
        second.token
    );
    repo.save_token(&parts, None).await.unwrap();
    repo.save_token(&parts, None).await.unwrap();
    assert!(repo.load_token(&parts).await.unwrap().is_none());
    repo.save_token(&parts, Some(&first)).await.unwrap();
    session.flush().await.unwrap();
    assert!(repo.load_token(&parts).await.unwrap().is_none());
}

#[tokio::test]
async fn missing_middleware_and_corrupt_session_data_are_errors() {
    let (parts, _) = Request::new(()).into_parts();
    assert!(matches!(
        HttpSessionCsrfTokenRepository::new()
            .load_token(&parts)
            .await,
        Err(CsrfRepositoryError::MissingSession)
    ));
    assert!(matches!(
        CookieCsrfTokenRepository::new().load_token(&parts).await,
        Err(CsrfRepositoryError::MissingCookies)
    ));
    let repo = HttpSessionCsrfTokenRepository::new().with_session_key("csrf");
    let parts = session_parts();
    parts
        .extensions
        .get::<Session>()
        .unwrap()
        .insert("csrf", 123)
        .await
        .unwrap();
    assert!(matches!(
        repo.load_token(&parts).await,
        Err(CsrfRepositoryError::Session(_))
    ));
}

#[tokio::test]
async fn cookie_jar_changes_are_visible_immediately_and_removal_is_idempotent() {
    let repo = CookieCsrfTokenRepository::new();
    let (mut parts, _) = Request::new(()).into_parts();
    let cookies = Cookies::default();
    parts.extensions.insert(cookies.clone());
    assert!(repo.load_token(&parts).await.unwrap().is_none());
    let token = repo.generate_token().unwrap();
    assert_eq!(token.header_name, "x-xsrf-token");
    assert_eq!(token.parameter_name, "_csrf");
    repo.save_token(&parts, Some(&token)).await.unwrap();
    assert_eq!(
        repo.load_token(&parts).await.unwrap().unwrap().token,
        token.token
    );
    let cookie = cookies.get("__Host-XSRF-TOKEN").unwrap();
    assert_eq!(cookie.path(), Some("/"));
    assert_eq!(cookie.domain(), None);
    assert_eq!(cookie.secure(), Some(true));
    assert_eq!(cookie.http_only(), Some(true));
    assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    repo.save_token(&parts, None).await.unwrap();
    repo.save_token(&parts, None).await.unwrap();
    assert!(repo.load_token(&parts).await.unwrap().is_none());
    cookies.add(Cookie::new("__Host-XSRF-TOKEN", "malformed-client-value"));
    assert!(repo.load_token(&parts).await.unwrap().is_none());
}

#[test]
fn cookie_configuration_enforces_cookie_names_and_prefixes() {
    for name in ["", "bad name", "bad;name", "bad=name", "bad\r\nname"] {
        assert!(
            CookieCsrfTokenRepository::new()
                .with_cookie_name(name)
                .is_err()
        );
    }
    assert!(CookieCsrfTokenRepository::new().with_secure(false).is_err());
    let local = CookieCsrfTokenRepository::new()
        .with_cookie_name("XSRF-TOKEN")
        .unwrap()
        .with_secure(false)
        .unwrap()
        .with_http_only(false);
    assert!(local.clone().with_cookie_name("__Host-XSRF-TOKEN").is_err());
    assert!(
        local
            .clone()
            .with_cookie_name("__Secure-XSRF-TOKEN")
            .is_err()
    );
    assert!(!local.secure);
    assert!(!local.http_only);
}

fn app(repo: Repository, mask_tokens: bool, use_session: bool) -> Router {
    let clear = repo.clone();
    let app = Router::new()
        .route(
            "/login",
            get(|Extension(token): Extension<CsrfToken>| async move { token.token })
                .post(|| async { "accepted" }),
        )
        .route(
            "/clear",
            get(move |request: Request<Body>| {
                let repo = clear.clone();
                async move {
                    let (parts, _) = request.into_parts();
                    repo.save_token(&parts, None).await.unwrap();
                    StatusCode::NO_CONTENT
                }
            }),
        )
        .layer(CsrfLayer::new(repo).mask_tokens(mask_tokens));
    if use_session {
        app.layer(SessionManagerLayer::new(MemoryStore::default()).with_secure(false))
    } else {
        app.layer(CookieManagerLayer::new())
    }
}

async fn page(app: &Router) -> (String, String, Vec<String>) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let set_cookies: Vec<String> = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .collect();
    let cookies = set_cookies
        .iter()
        .map(|c| c.split(';').next().unwrap())
        .collect::<Vec<_>>()
        .join("; ");
    let token =
        String::from_utf8(to_bytes(response.into_body(), 4096).await.unwrap().to_vec()).unwrap();
    (token, cookies, set_cookies)
}

#[tokio::test]
async fn session_tokens_support_masked_forms_and_do_not_cross_sessions() {
    let app = app(Arc::new(HttpSessionCsrfTokenRepository::new()), true, true);
    let (token, cookies, _) = page(&app).await;
    let (_, other_cookies, _) = page(&app).await;
    for (cookie, status) in [
        (cookies.as_str(), StatusCode::OK),
        (other_cookies.as_str(), StatusCode::FORBIDDEN),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login")
                    .header(header::COOKIE, cookie)
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(format!("_csrf={token}")))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), status);
    }
}

#[tokio::test]
async fn cookie_repository_supports_ajax_without_creating_a_server_session() {
    let repo = CookieCsrfTokenRepository::new().with_http_only(false);
    let app = app(Arc::new(repo), false, false);
    let (token, cookies, set_cookies) = page(&app).await;
    assert_eq!(set_cookies.len(), 1);
    assert!(set_cookies[0].starts_with("__Host-XSRF-TOKEN="));
    assert!(set_cookies[0].contains("Secure"));
    assert!(!set_cookies[0].contains("HttpOnly"));
    assert_eq!(cookies, format!("__Host-XSRF-TOKEN={token}"));
    for (cookie, submitted, status) in [
        (cookies.as_str(), token.as_str(), StatusCode::OK),
        (cookies.as_str(), "wrong", StatusCode::FORBIDDEN),
        ("", token.as_str(), StatusCode::FORBIDDEN),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login")
                    .header(header::COOKIE, cookie)
                    .header("x-xsrf-token", submitted)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), status);
    }
    let response = app
        .oneshot(
            Request::builder()
                .uri("/clear")
                .header(header::COOKIE, &cookies)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let removed = response.headers()[header::SET_COOKIE].to_str().unwrap();
    assert!(removed.starts_with("__Host-XSRF-TOKEN="));
    assert!(removed.contains("Max-Age=0"));
    assert!(removed.contains("Path=/"));
}

#[tokio::test]
async fn cookie_repository_also_accepts_masked_form_tokens() {
    let app = app(Arc::new(CookieCsrfTokenRepository::new()), true, false);
    let (token, cookies, _) = page(&app).await;
    assert_ne!(cookies, format!("__Host-XSRF-TOKEN={token}"));
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header(header::COOKIE, cookies)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!("_csrf={token}")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

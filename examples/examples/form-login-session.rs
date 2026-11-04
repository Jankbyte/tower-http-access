//! Form login with server-side sessions. Run:
//! `cargo run -p tower-http-access-examples --example form-login-session`
//! Open http://127.0.0.1:3000 and log in as alice / change-me.
//! Basic clients can access `/private` without creating a session:
//! `curl -u alice:change-me http://127.0.0.1:3000/private`
//! Uses an in-memory session store and a demonstration account. For deployment,
//! use HTTPS, secure cookies, a persistent store, and your application's public origin.
use argon2::Argon2;
use axum::{
    Form, Router,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{Html, Redirect},
    routing::get,
};
use futures_util::future::BoxFuture;
use serde::Deserialize;
use std::{num::NonZeroUsize, sync::Arc};
use tower_http_access::{
    SecurityChainLayer, SecurityLayer, authentication::Authenticated,
    authorization::RequestAuthorizationProvider, request_matcher::RequestMatcher,
};
use tower_http_access_basic::{
    AsyncStringPasswordManager, BasicCredentials, BasicRequestAuthenticator,
    InMemoryUserDetailService, UserDetail, UserDetailAuthenticationProvider, UserDetailService,
    UserLoadingError, UsernamePasswordAuthenticationProvider,
};
use tower_http_access_session::{
    SessionIdentityProvider, SessionRequestAuthenticator, initialize_session,
};
use tower_sessions::{
    Expiry, MemoryStore, Session, SessionManagerLayer,
    cookie::{SameSite, time::Duration},
};

const ORIGIN: &str = "http://127.0.0.1:3000";
type WebError = (StatusCode, &'static str);

// Select HTML-oriented requests, rather than relying on User-Agent strings.
// This is content negotiation, not proof that the caller is a browser.
struct BrowserRequestMatcher;
impl RequestMatcher for BrowserRequestMatcher {
    fn matches(&self, request: &axum::http::request::Parts) -> bool {
        request.headers.get_all(header::ACCEPT).iter().any(|value| {
            value.to_str().is_ok_and(|value| {
                value.split(',').any(|range| {
                    let mut parts = range.split(';');
                    parts
                        .next()
                        .is_some_and(|media| media.trim().eq_ignore_ascii_case("text/html"))
                        && !parts.any(|parameter| {
                            parameter
                                .trim()
                                .split_once('=')
                                .is_some_and(|(name, value)| {
                                    name.trim().eq_ignore_ascii_case("q")
                                        && value
                                            .trim()
                                            .parse::<f32>()
                                            .is_ok_and(|quality| quality == 0.0)
                                })
                        })
                })
            })
        })
    }
}

// Explicit Basic credentials take precedence over HTML content negotiation.
struct BasicRequestMatcher;
impl RequestMatcher for BasicRequestMatcher {
    fn matches(&self, request: &axum::http::request::Parts) -> bool {
        request
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split_ascii_whitespace().next())
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("Basic"))
    }
}

struct Users(InMemoryUserDetailService);
impl SessionIdentityProvider for Users {
    type Id = String;
    type Identity = UserDetail;
    type Error = UserLoadingError;

    fn load_identity<'a>(
        &'a self,
        id: String,
    ) -> BoxFuture<'a, Result<Option<UserDetail>, UserLoadingError>> {
        // Reload the current user and authorities for each authenticated request.
        Box::pin(async move { self.0.load_user_by_name(&id).await })
    }
}

struct LoginState {
    credentials: UserDetailAuthenticationProvider<
        AsyncStringPasswordManager<Argon2<'static>>,
        InMemoryUserDetailService,
    >,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = create_app().await?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn create_app() -> Result<Router, Box<dyn std::error::Error + Send + Sync>> {
    let passwords = AsyncStringPasswordManager::new(
        tokio::runtime::Handle::current(),
        Argon2::default(),
        NonZeroUsize::new(2).unwrap(),
    );
    // The constructor hashes these demonstration passwords at startup.
    let users = InMemoryUserDetailService::new((
        &passwords,
        vec![
            UserDetail::new("alice", "change-me", vec![]),
            UserDetail::new("bob", "bob-password", vec![]),
        ],
    ))
    .await?;
    let session_users = Users(users.clone());
    let credentials = UserDetailAuthenticationProvider::new(passwords, users).await?;
    let basic = Arc::new(BasicRequestAuthenticator::new(credentials.clone()));
    let basic_authorizer = RequestAuthorizationProvider::<UserDetail>::builder()
        .request_matchers("/private")
        .authenticated()
        // Form handlers require a browser session and are outside this chain.
        .any_request()
        .deny_all()
        .build()?;
    let basic_security =
        SecurityLayer::new(Arc::clone(&basic), basic_authorizer).authentication_entry_point(basic);
    let state = Arc::new(LoginState { credentials });
    let authorizer = RequestAuthorizationProvider::<UserDetail>::builder()
        .request_matchers("/")
        .permit_all()
        .request_matchers("/login")
        .permit_all()
        .request_matchers("/logout")
        .permit_all()
        .any_request()
        .authenticated()
        .build()?;
    let security = SecurityLayer::new(SessionRequestAuthenticator::new(session_users), authorizer)
        .authentication_entry_point(|_: &axum::http::request::Parts| {
            let mut response = tower_http_access::SecurityResponse::new(Default::default());
            *response.status_mut() = StatusCode::SEE_OTHER;
            response
                .headers_mut()
                .insert(header::LOCATION, "/login".parse().unwrap());
            response
        });
    // These layers run only when the browser chain is selected.
    let browser_stack = tower::ServiceBuilder::new()
        .layer(
            SessionManagerLayer::new(MemoryStore::default())
                .with_secure(false) // Local HTTP demonstration only.
                .with_http_only(true)
                .with_same_site(SameSite::Strict)
                .with_expiry(Expiry::OnInactivity(Duration::minutes(30))),
        )
        .layer(axum::middleware::from_fn(anonymous_session))
        .layer(security);
    let chains = SecurityChainLayer::builder()
        .chain(BasicRequestMatcher, basic_security)
        .chain(BrowserRequestMatcher, browser_stack)
        .fallback_deny()
        .build()?;
    Ok(Router::new()
        .route("/", get(|| async { Redirect::to("/private") }))
        .route("/login", get(login_form).post(login))
        .route("/logout", axum::routing::post(logout))
        .route("/private", get(private))
        .with_state(state)
        .layer(chains))
}

// Runs inside SessionManagerLayer and before request handlers.
async fn anonymous_session(
    session: Session,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, WebError> {
    initialize_session(&session).await.map_err(session_error)?;
    Ok(next.run(request).await)
}

async fn login_form() -> Html<&'static str> {
    Html(
        r#"<!doctype html><html lang="en"><title>Sign in</title>
<h1>Sign in</h1><p>Demo: alice / change-me</p>
<form method="post" action="/login">
<label>Username <input name="username" autocomplete="username" required></label>
<label>Password <input name="password" type="password" autocomplete="current-password" required></label>
<button>Sign in</button></form></html>"#,
    )
}

#[derive(Deserialize)]
struct Credentials {
    username: String,
    password: String,
}

// Reject cross-origin form submissions, including login and logout CSRF.
// The configured origin is trusted; do not derive it from incoming Host headers.
fn check_origin(headers: &HeaderMap) -> Result<(), WebError> {
    if headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        == Some(ORIGIN)
    {
        Ok(())
    } else {
        Err((StatusCode::FORBIDDEN, "Invalid form origin"))
    }
}

fn session_error(_: tower_sessions::session::Error) -> WebError {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "Session operation failed",
    )
}

async fn login(
    State(state): State<Arc<LoginState>>,
    session: Session,
    headers: HeaderMap,
    Form(credentials): Form<Credentials>,
) -> Result<Redirect, WebError> {
    check_origin(&headers)?;
    let user = state
        .credentials
        .authenticate(&BasicCredentials {
            username: credentials.username,
            password: credentials.password,
        })
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Authentication failed"))?
        .ok_or((StatusCode::UNAUTHORIZED, "Invalid username or password"))?;
    // Rotate the identifier before establishing an authenticated session.
    session.cycle_id().await.map_err(session_error)?;
    session
        .insert("user_id", user.username)
        .await
        .map_err(session_error)?;
    Ok(Redirect::to("/private"))
}

async fn private(Authenticated(user): Authenticated<UserDetail>) -> Html<String> {
    let username = user
        .username
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;");
    Html(format!(
        r#"<!doctype html><html lang="en"><title>Private page</title>
<h1>Hello, {username}!</h1><p>You are authenticated through your session.</p>
<form method="post" action="/logout"><button>Sign out</button></form></html>"#,
    ))
}

async fn logout(session: Session, headers: HeaderMap) -> Result<Redirect, WebError> {
    check_origin(&headers)?;
    session.flush().await.map_err(session_error)?;
    Ok(Redirect::to("/login"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    #[tokio::test]
    async fn basic_chain_skips_sessions_even_when_html_is_accepted() {
        let app = create_app().await.unwrap();
        for (path, credentials, status) in [
            ("/private", "Basic YWxpY2U6Y2hhbmdlLW1l", StatusCode::OK),
            (
                "/private",
                "Basic YWxpY2U6d3Jvbmc=",
                StatusCode::UNAUTHORIZED,
            ),
            ("/private", "Basic invalid!", StatusCode::UNAUTHORIZED),
            (
                "/login",
                "Basic YWxpY2U6Y2hhbmdlLW1l",
                StatusCode::FORBIDDEN,
            ),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .header(header::ACCEPT, "text/html")
                        .header(header::AUTHORIZATION, credentials)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), status);
            assert!(!response.headers().contains_key(header::SET_COOKIE));
            assert!(!response.headers().contains_key(header::LOCATION));
            if status == StatusCode::UNAUTHORIZED {
                assert!(response.headers().contains_key(header::WWW_AUTHENTICATE));
            }
        }
    }

    #[tokio::test]
    async fn non_html_requests_are_denied() {
        let app = create_app().await.unwrap();
        for accept in [None, Some("application/json"), Some("text/html;q=0")] {
            let mut request = Request::builder().uri("/private");
            if let Some(accept) = accept {
                request = request.header(header::ACCEPT, accept);
            }
            let response = app
                .clone()
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            assert!(!response.headers().contains_key(header::LOCATION));
        }
    }

    #[tokio::test]
    async fn form_login_session_and_logout() {
        let app = create_app().await.unwrap();
        let login_page = app
            .clone()
            .oneshot(
                Request::builder()
                    .header(header::ACCEPT, "text/html")
                    .uri("/login")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(login_page.status(), StatusCode::OK);
        assert!(login_page.headers().contains_key(header::SET_COOKIE));
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .header(header::ACCEPT, "text/html")
                    .uri("/private")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers()[header::LOCATION], "/login");
        for (origin, username, password, status) in [
            (
                "http://evil.example",
                "alice",
                "change-me",
                StatusCode::FORBIDDEN,
            ),
            (ORIGIN, "alice", "wrong", StatusCode::UNAUTHORIZED),
            (ORIGIN, "unknown", "change-me", StatusCode::UNAUTHORIZED),
            (ORIGIN, "alice", "change-me", StatusCode::SEE_OTHER),
            (ORIGIN, "bob", "bob-password", StatusCode::SEE_OTHER),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .header(header::ACCEPT, "text/html")
                        .method("POST")
                        .uri("/login")
                        .header(header::ORIGIN, origin)
                        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                        .body(Body::from(format!(
                            "username={username}&password={password}"
                        )))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), status);
            if status != StatusCode::SEE_OTHER {
                continue;
            }
            let cookie = response.headers()[header::SET_COOKIE]
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .to_owned();
            let request = |method, path| {
                Request::builder()
                    .header(header::ACCEPT, "text/html")
                    .method(method)
                    .uri(path)
                    .header(header::COOKIE, &cookie)
                    .header(header::ORIGIN, ORIGIN)
                    .body(Body::empty())
                    .unwrap()
            };
            let response = app
                .clone()
                .oneshot(request("GET", "/private"))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            assert!(
                std::str::from_utf8(&body)
                    .unwrap()
                    .contains(&format!("Hello, {username}!"))
            );
            assert_eq!(
                app.clone()
                    .oneshot(request("POST", "/logout"))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::SEE_OTHER
            );
            assert_eq!(
                app.clone()
                    .oneshot(request("GET", "/private"))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::SEE_OTHER
            );
        }
    }
}

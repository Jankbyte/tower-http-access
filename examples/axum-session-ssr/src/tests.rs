use super::*;
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use tower::ServiceExt;

async fn login_form(app: &Router) -> (String, String) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(LOGIN_PAGE_PATH)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = response.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let html = String::from_utf8(
        to_bytes(response.into_body(), 65536)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    let token = html
        .split("name=\"_csrf\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned();
    assert!(!token.is_empty());
    assert!(!html.contains("<script"));
    (cookie, token)
}

#[tokio::test]
async fn html_login_validates_the_hidden_csrf_token_before_credentials() {
    let app = create_app().await.unwrap();
    let (cookie, token) = login_form(&app).await;
    let (other_cookie, _) = login_form(&app).await;
    for (cookie, csrf, password, expected, location) in [
        (cookie.as_str(), "", "crab123", StatusCode::FORBIDDEN, None),
        (
            cookie.as_str(),
            "wrong",
            "crab123",
            StatusCode::FORBIDDEN,
            None,
        ),
        (
            other_cookie.as_str(),
            token.as_str(),
            "crab123",
            StatusCode::FORBIDDEN,
            None,
        ),
        (
            cookie.as_str(),
            token.as_str(),
            "wrong",
            StatusCode::SEE_OTHER,
            Some("/auth/login?error=true"),
        ),
        (
            cookie.as_str(),
            token.as_str(),
            "crab123",
            StatusCode::SEE_OTHER,
            Some("/"),
        ),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(LOGIN_PAGE_PATH)
                    .header(header::COOKIE, cookie)
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(format!(
                        "username=crab&password={password}&_csrf={csrf}"
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        assert_eq!(
            response
                .headers()
                .get(header::LOCATION)
                .map(|v| v.to_str().unwrap()),
            location
        );
        if password == "crab123" && expected == StatusCode::SEE_OTHER {
            assert!(response.headers().contains_key(header::SET_COOKIE));
        }
    }
}

#[tokio::test]
async fn logout_requires_csrf_and_invalidates_the_session() {
    let app = create_app().await.unwrap();
    let (anonymous_cookie, token) = login_form(&app).await;
    let login = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(LOGIN_PAGE_PATH)
                .header(header::COOKIE, anonymous_cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "username=crab&password=crab123&_csrf={token}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::SEE_OTHER);
    let cookie = login.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();

    let get_me = || {
        Request::builder()
            .uri("/me")
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap()
    };
    let page = app.clone().oneshot(get_me()).await.unwrap();
    assert_eq!(page.status(), StatusCode::OK);
    let html =
        String::from_utf8(to_bytes(page.into_body(), 65536).await.unwrap().to_vec()).unwrap();
    assert!(html.contains("action=\"/auth/logout\""));
    let token = html
        .split("name=\"_csrf\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();

    let get_logout = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(LOGOUT_PAGE_PATH)
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get_logout.status(), StatusCode::METHOD_NOT_ALLOWED);
    for body in [String::new(), "_csrf=invalid".into()] {
        let rejected = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(LOGOUT_PAGE_PATH)
                    .header(header::COOKIE, &cookie)
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rejected.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            app.clone().oneshot(get_me()).await.unwrap().status(),
            StatusCode::OK
        );
    }

    let logout = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(LOGOUT_PAGE_PATH)
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!("_csrf={token}")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(logout.status(), StatusCode::SEE_OTHER);
    assert_eq!(logout.headers()[header::LOCATION], LOGIN_PAGE_PATH);
    assert!(
        logout.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );

    let replay = app.clone().oneshot(get_me()).await.unwrap();
    assert_eq!(replay.status(), StatusCode::FOUND);
    assert_eq!(replay.headers()[header::LOCATION], LOGIN_PAGE_PATH);
    let replay_csrf = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(LOGOUT_PAGE_PATH)
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!("_csrf={token}")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(replay_csrf.status(), StatusCode::FORBIDDEN);
}

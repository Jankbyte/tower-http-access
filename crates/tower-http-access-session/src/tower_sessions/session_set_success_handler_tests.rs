use super::SessionSetSuccessHandler;
use bytes::Bytes;
use futures_util::future::BoxFuture;
use http::{Method, Request, Response, StatusCode, header};
use http_body_util::BodyExt;
use http_request_matcher::RequestMatcher;
use tower_http_access_core::SecurityResponse;
use tower_http_access_form_login::*;
use tower_layer::Layer;
use user_password_auth::{Credentials, UsernamePasswordAuthenticationProvider};

fn response(status: StatusCode) -> SecurityResponse {
    Response::builder()
        .status(status)
        .body(Bytes::new())
        .unwrap()
}
use http::request::Parts;
use http_body_util::Full;
use std::convert::Infallible;
use std::sync::Arc;
use tower::ServiceExt;

#[derive(Clone)]
struct Provider;
impl UsernamePasswordAuthenticationProvider for Provider {
    type Authentication = String;
    type Error = std::io::Error;
    fn authenticate<'a>(
        &'a self,
        credentials: &'a Credentials,
    ) -> BoxFuture<'a, Result<Option<String>, Self::Error>> {
        Box::pin(async move {
            if credentials.username == "backend" {
                return Err(std::io::Error::other("backend unavailable"));
            }
            Ok(
                (credentials.username == "alice" && credentials.password == "p+ss word")
                    .then(|| credentials.username.clone()),
            )
        })
    }
}

fn request(method: Method, path: &str, body: &'static str) -> Request<Full<Bytes>> {
    Request::builder()
        .method(method)
        .uri(path)
        .header(
            header::CONTENT_TYPE,
            "application/x-www-form-urlencoded; charset=UTF-8",
        )
        .body(Full::new(Bytes::from_static(body.as_bytes())))
        .unwrap()
}

async fn run<P, M, H, F>(
    layer: FormLoginLayer<P, M, H, F>,
    request: Request<Full<Bytes>>,
) -> Response<Bytes>
where
    P: UsernamePasswordAuthenticationProvider + Clone + 'static,
    M: RequestMatcher + Clone + 'static,
    H: SuccessHandler<P::Authentication> + Clone + 'static,
    F: FailureHandler + Clone + 'static,
{
    layer
        .layer(tower::service_fn(
            |request: Request<Full<Bytes>>| async move {
                let body = request.into_body().collect().await.unwrap().to_bytes();
                Ok::<_, Infallible>(
                    Response::builder()
                        .status(StatusCode::ACCEPTED)
                        .body(body)
                        .unwrap(),
                )
            },
        ))
        .oneshot(request)
        .await
        .unwrap()
}

#[tokio::test]
async fn session_success_rotates_stores_and_then_delegates() {
    use ::tower_sessions::{MemoryStore, Session};
    let store = Arc::new(MemoryStore::default());
    let session = Session::new(None, store.clone(), None);
    session.insert("existing", true).await.unwrap();
    session.save().await.unwrap();
    let old_id = session.id();
    let handler = SessionSetSuccessHandler::new(
        |identity: &String| identity.clone(),
        |parts: Parts, identity: String| async move {
            let session = parts.extensions.get::<Session>().unwrap();
            assert_eq!(
                session.get::<String>("user_id").await.unwrap(),
                Some(identity)
            );
            assert_eq!(session.get::<bool>("existing").await.unwrap(), Some(true));
            Response::builder()
                .status(StatusCode::SEE_OTHER)
                .header(header::LOCATION, "/private")
                .body(Bytes::new())
                .unwrap()
        },
    );
    let mut req = request(
        Method::POST,
        "/login",
        "username=alice&password=p%2Bss+word",
    );
    req.extensions_mut().insert(session.clone());
    let result = run(FormLoginLayer::new(Provider).on_success(handler), req).await;
    assert_eq!(result.status(), StatusCode::SEE_OTHER);
    assert_eq!(result.headers()[header::LOCATION], "/private");
    session.save().await.unwrap();
    assert_ne!(session.id(), old_id);
    let restored = Session::new(session.id(), store.clone(), None);
    assert_eq!(
        restored.get::<String>("user_id").await.unwrap().as_deref(),
        Some("alice")
    );
    let previous = Session::new(old_id, store, None);
    assert_eq!(previous.get::<String>("user_id").await.unwrap(), None);
}

#[tokio::test]
async fn session_success_supports_custom_key_and_requires_session() {
    use ::tower_sessions::{MemoryStore, Session};
    let handler = SessionSetSuccessHandler::new(
        |identity: &String| identity.clone(),
        |_: Parts, _: String| async { response(StatusCode::NO_CONTENT) },
    )
    .with_session_key("principal");
    let layer = FormLoginLayer::new(Provider).on_success(handler);
    let body = "username=alice&password=p%2Bss+word";
    assert_eq!(
        run(layer.clone(), request(Method::POST, "/login", body))
            .await
            .status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    let session = Session::new(None, Arc::new(MemoryStore::default()), None);
    let mut req = request(Method::POST, "/login", body);
    req.extensions_mut().insert(session.clone());
    assert_eq!(run(layer, req).await.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        session.get::<String>("principal").await.unwrap().as_deref(),
        Some("alice")
    );
    assert_eq!(session.get::<String>("user_id").await.unwrap(), None);
}

#[tokio::test]
async fn session_success_does_not_delegate_on_serialization_failure() {
    use ::tower_sessions::{MemoryStore, Session};
    struct Unserializable;
    impl serde::Serialize for Unserializable {
        fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom("cannot serialize identity"))
        }
    }
    let handler = SessionSetSuccessHandler::new(
        |_: &String| Unserializable,
        |_: Parts, _: String| async { panic!("must not delegate after session failure") },
    );
    let mut req = request(
        Method::POST,
        "/login",
        "username=alice&password=p%2Bss+word",
    );
    req.extensions_mut()
        .insert(Session::new(None, Arc::new(MemoryStore::default()), None));
    assert_eq!(
        run(FormLoginLayer::new(Provider).on_success(handler), req)
            .await
            .status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
}

#[tokio::test]
async fn builtin_success_handlers_return_ok_or_redirect() {
    let body = "username=alice&password=p%2Bss+word";
    let result = run(
        FormLoginLayer::new(Provider).on_success(DefaultSuccessHandler),
        request(Method::POST, "/login", body),
    )
    .await;
    assert_eq!(result.status(), StatusCode::OK);
    assert!(result.body().is_empty());
    assert!(!result.headers().contains_key(header::LOCATION));

    let session =
        tower_sessions::Session::new(None, Arc::new(tower_sessions::MemoryStore::default()), None);
    let handler = SessionSetSuccessHandler::new(
        |user: &String| user.clone(),
        RedirectSuccessHandler::new("/private?welcome=true").unwrap(),
    );
    let mut req = request(Method::POST, "/login", body);
    req.extensions_mut().insert(session.clone());
    let result = run(FormLoginLayer::new(Provider).on_success(handler), req).await;
    assert_eq!(result.status(), StatusCode::SEE_OTHER);
    assert_eq!(result.headers()[header::LOCATION], "/private?welcome=true");
    assert!(result.body().is_empty());
    assert_eq!(
        session.get::<String>("user_id").await.unwrap().as_deref(),
        Some("alice")
    );
}

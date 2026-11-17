use base64::{Engine, engine::general_purpose::STANDARD};
use criterion::{Criterion, criterion_group, criterion_main};
use futures_util::future::BoxFuture;
use http::{Request, StatusCode, header};
use std::{hint::black_box, io};
use tower_http_access_basic::BasicRequestAuthenticator;
use tower_http_access_core::authentication::{AuthenticationAttempt, RequestAuthenticator};
use user_password_auth::{Credentials, UsernamePasswordAuthenticationProvider};

struct StubProvider {
    fail: bool,
}

impl UsernamePasswordAuthenticationProvider for StubProvider {
    type Authentication = u64;
    type Error = io::Error;

    fn authenticate<'a>(
        &'a self,
        credentials: &'a Credentials,
    ) -> BoxFuture<'a, Result<Option<Self::Authentication>, Self::Error>> {
        Box::pin(async move {
            if self.fail {
                return Err(io::Error::other("benchmark provider failure"));
            }
            Ok((credentials.username == "alex" && credentials.password == "secret").then_some(42))
        })
    }
}

enum Expected {
    NotApplicable,
    Authenticated,
    Failure(StatusCode),
}

fn basic_authenticator(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let basic = |credentials: &[u8]| format!("Basic {}", STANDARD.encode(credentials));
    let cases = [
        ("missing_header", None, false, Expected::NotApplicable),
        (
            "other_scheme",
            Some("Bearer token".to_owned()),
            false,
            Expected::NotApplicable,
        ),
        (
            "valid_credentials",
            Some(basic(b"alex:secret")),
            false,
            Expected::Authenticated,
        ),
        (
            "malformed_base64",
            Some("Basic !!!".to_owned()),
            false,
            Expected::Failure(StatusCode::UNAUTHORIZED),
        ),
        (
            "missing_colon",
            Some(basic(b"alex")),
            false,
            Expected::Failure(StatusCode::UNAUTHORIZED),
        ),
        (
            "invalid_utf8",
            Some(basic(b"alex:\xff")),
            false,
            Expected::Failure(StatusCode::UNAUTHORIZED),
        ),
        (
            "rejected_credentials",
            Some(basic(b"alex:wrong")),
            false,
            Expected::Failure(StatusCode::UNAUTHORIZED),
        ),
        (
            "provider_error",
            Some(basic(b"alex:secret")),
            true,
            Expected::Failure(StatusCode::INTERNAL_SERVER_ERROR),
        ),
    ];

    let mut group = c.benchmark_group("basic_authenticator");
    for (name, authorization, fail, expected) in cases {
        let authenticator = BasicRequestAuthenticator::new(StubProvider { fail });
        let mut request = Request::builder().uri("/private");
        if let Some(authorization) = authorization {
            request = request.header(header::AUTHORIZATION, authorization);
        }
        let (parts, ()) = request.body(()).unwrap().into_parts();

        // Check the intended branch once, outside the measured loop.
        let result = runtime.block_on(authenticator.authenticate(&parts));
        match expected {
            Expected::NotApplicable => {
                assert_eq!(result.unwrap(), AuthenticationAttempt::NotApplicable);
            }
            Expected::Authenticated => {
                assert_eq!(result.unwrap(), AuthenticationAttempt::Authenticated(42));
            }
            Expected::Failure(status) => {
                let response = result.unwrap_err().into_security_response();
                assert_eq!(response.status(), status);
                if status == StatusCode::UNAUTHORIZED {
                    assert_eq!(
                        response.headers()[header::WWW_AUTHENTICATE],
                        r#"Basic realm="Default""#,
                    );
                }
            }
        }

        group.bench_function(name, |b| {
            b.to_async(&runtime)
                .iter(|| async { black_box(authenticator.authenticate(black_box(&parts)).await) });
        });
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().output_directory(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/criterion"),
    );
    targets = basic_authenticator
}
criterion_main!(benches);

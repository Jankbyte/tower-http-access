pub use tower_http_access_core::{SecurityLayer, authentication};

mod response {
    use bytes::Bytes;
    use http::{Response, StatusCode};
    pub use tower_http_access_core::SecurityResponse;
    #[cfg(feature = "split_auth")]
    pub use tower_http_access_core::SecurityResponseAdapter;
    pub(crate) fn test_response(status: StatusCode, body: impl Into<Bytes>) -> SecurityResponse {
        let mut response = Response::new(body.into());
        *response.status_mut() = status;
        response
    }
    #[cfg(feature = "split_auth")]
    mod tests {
        include!("support/response_tests.rs");
    }
}

#[cfg(feature = "split_auth")]
mod authorization {
    pub mod core {
        pub use tower_http_access_core::authorization::core::*;

        pub(crate) fn assert_builtin_decision(
            actual: AuthorizationDecision,
            expected: AuthorizationDecision,
        ) {
            assert!(
                matches!(
                    (&actual, &expected),
                    (AuthorizationDecision::Allow, AuthorizationDecision::Allow)
                        | (
                            AuthorizationDecision::Deny(
                                AuthorizationDenial::AuthenticationRequired
                            ),
                            AuthorizationDecision::Deny(
                                AuthorizationDenial::AuthenticationRequired
                            )
                        )
                        | (
                            AuthorizationDecision::Deny(
                                AuthorizationDenial::InsufficientPermissions
                            ),
                            AuthorizationDecision::Deny(
                                AuthorizationDenial::InsufficientPermissions
                            )
                        )
                ),
                "expected {expected:?}, got {actual:?}"
            );
        }
    }
    pub mod auth_tower {
        use std::pin::Pin;
        pub use tower_http_access_core::authorization::auth_tower::*;
        use tower_http_access_core::authorization::core::*;
        pub mod tests {
            include!("support/auth_tower_tests.rs");
        }
    }
    mod all_tests {
        include!("support/all_tests.rs");
    }
}

mod combined {
    use futures_util::future::BoxFuture;
    use std::task::{Context, Poll};
    use tower_http_access_core::authentication::{
        Authenticated, AuthenticationAttempt, RequestAuthenticator,
    };
    use tower_http_access_core::authorization::core::*;
    use tower_http_access_core::*;
    use tower_layer::Layer;
    use tower_service::Service;
    mod tests {
        include!("support/combined_tests.rs");
    }
}

#[cfg(feature = "filter_chain")]
mod filter_chain {
    use bytes::Bytes;
    use http::{Request, Response, StatusCode};
    use std::{
        sync::Arc,
        task::{Context, Poll},
    };
    use tower::ServiceExt;
    use tower_http_access_core::filter_chain::*;
    use tower_layer::Layer;
    use tower_service::Service;
    mod tests {
        include!("support/filter_chain_tests.rs");
    }
}

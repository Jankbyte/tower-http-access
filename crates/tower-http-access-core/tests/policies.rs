pub use tower_http_access_core::{SecurityLayer, authentication};

mod response {
    use bytes::Bytes;
    use http::{Response, StatusCode};
    pub use tower_http_access_core::SecurityResponse;
    pub use tower_http_access_core::SecurityResponseAdapter;
    pub(crate) fn test_response(status: StatusCode, body: impl Into<Bytes>) -> SecurityResponse {
        let mut response = Response::new(body.into());
        *response.status_mut() = status;
        response
    }
    mod tests {
        include!("support/response_tests.rs");
    }
}

mod authorization {
    pub use tower_http_access_core::authorization::*;

    pub(crate) fn assert_builtin_decision(
        actual: AuthorizationDecision,
        expected: AuthorizationDecision,
    ) {
        assert!(
            matches!(
                (&actual, &expected),
                (AuthorizationDecision::Allow, AuthorizationDecision::Allow)
                    | (
                        AuthorizationDecision::Deny(AuthorizationDenial::AuthenticationRequired),
                        AuthorizationDecision::Deny(AuthorizationDenial::AuthenticationRequired)
                    )
                    | (
                        AuthorizationDecision::Deny(AuthorizationDenial::InsufficientPermissions),
                        AuthorizationDecision::Deny(AuthorizationDenial::InsufficientPermissions)
                    )
            ),
            "expected {expected:?}, got {actual:?}"
        );
    }
    pub mod provider_tests {
        use tower_http_access_core::authorization::*;
        pub mod tests {
            include!("support/authorization_tests.rs");
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
    use tower_http_access_core::authorization::*;
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

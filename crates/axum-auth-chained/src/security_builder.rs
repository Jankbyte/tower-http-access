use tower::ServiceBuilder;
use tower_layer::{Identity, Stack};

use crate::{
    authentication::{
        AuthenticationLayer, DelegatingRequestAuthenticator, DelegatingRequestAuthenticatorBuilder,
        RequestAuthenticator,
    },
    authorization::{
        AuthenticationEntryPoint, AuthorizationFailureHandler, AuthorizationLayer,
        AuthorizationProvider, DefaultAuthenticationEntryPoint, DefaultAuthorizationFailureHandler,
    },
};

/// Configures the authorization part of a security layer.
pub struct AuthorizationCustomizer<
    P = (),
    E = DefaultAuthenticationEntryPoint,
    H = DefaultAuthorizationFailureHandler,
> {
    provider: P,
    authentication_entry_point: E,
    failure_handler: H,
}

impl Default for AuthorizationCustomizer {
    fn default() -> Self {
        Self {
            provider: (),
            authentication_entry_point: DefaultAuthenticationEntryPoint,
            failure_handler: DefaultAuthorizationFailureHandler,
        }
    }
}

impl<E, H> AuthorizationCustomizer<(), E, H> {
    /// Selects the authorization provider.
    pub fn authorize_with<P>(self, provider: P) -> AuthorizationCustomizer<P, E, H> {
        AuthorizationCustomizer {
            provider,
            authentication_entry_point: self.authentication_entry_point,
            failure_handler: self.failure_handler,
        }
    }
}

impl<P, E, H> AuthorizationCustomizer<P, E, H> {
    /// Replaces the default authentication entry point.
    pub fn authentication_entry_point<NewEntryPoint>(
        self,
        authentication_entry_point: NewEntryPoint,
    ) -> AuthorizationCustomizer<P, NewEntryPoint, H> {
        AuthorizationCustomizer {
            provider: self.provider,
            authentication_entry_point,
            failure_handler: self.failure_handler,
        }
    }

    /// Replaces the default authorization failure handler.
    pub fn failure_handler<NewHandler>(
        self,
        failure_handler: NewHandler,
    ) -> AuthorizationCustomizer<P, E, NewHandler> {
        AuthorizationCustomizer {
            provider: self.provider,
            authentication_entry_point: self.authentication_entry_point,
            failure_handler,
        }
    }
}

enum AuthorizationConfiguration<P, E, H> {
    Configure(AuthorizationCustomizer<P, E, H>),
    Ready(AuthorizationLayer<P, H, E>),
}

/// Builds authentication and authorization middleware.
///
/// `A` is the concrete authenticator type. Use [`Self::authenticator`] for a
/// single mechanism or [`Self::chained_authenticators`] for an ordered chain.
pub struct SecurityLayerBuilder<
    A = (),
    P = (),
    E = DefaultAuthenticationEntryPoint,
    H = DefaultAuthorizationFailureHandler,
> {
    authenticator: A,
    authorization: AuthorizationConfiguration<P, E, H>,
}

impl SecurityLayerBuilder {
    /// Starts building security middleware.
    pub fn builder() -> Self {
        Self {
            authenticator: (),
            authorization: AuthorizationConfiguration::Configure(AuthorizationCustomizer::default()),
        }
    }

    /// Sets one authenticator directly, without an authentication chain.
    /// The authenticator does not need to implement `Clone`.
    pub fn authenticator<A: RequestAuthenticator>(
        self,
        authenticator: A,
    ) -> SecurityLayerBuilder<A> {
        SecurityLayerBuilder {
            authenticator,
            authorization: self.authorization,
        }
    }

    /// Configures the ordered authentication chain.
    pub fn chained_authenticators<A, C>(
        self,
        customize: C,
    ) -> SecurityLayerBuilder<DelegatingRequestAuthenticator<A>>
    where
        A: Clone + Send + Sync + 'static,
        C: FnOnce(
            DelegatingRequestAuthenticatorBuilder<A>,
        ) -> DelegatingRequestAuthenticatorBuilder<A>,
    {
        SecurityLayerBuilder {
            authenticator: customize(DelegatingRequestAuthenticator::builder()).build(),
            authorization: self.authorization,
        }
    }
}

impl<A: RequestAuthenticator> SecurityLayerBuilder<A> {
    /// Uses an already configured authorization layer, preserving its handlers and provider.
    pub fn authorization_layer<P, H, E>(
        self,
        layer: AuthorizationLayer<P, H, E>,
    ) -> SecurityLayerBuilder<A, P, E, H>
    where
        P: AuthorizationProvider<Authentication = A::Authentication>,
    {
        SecurityLayerBuilder {
            authenticator: self.authenticator,
            authorization: AuthorizationConfiguration::Ready(layer),
        }
    }

    /// Configures authorization.
    pub fn authorization<NewP, NewE, NewH, C>(
        self,
        customize: C,
    ) -> SecurityLayerBuilder<A, NewP, NewE, NewH>
    where
        C: FnOnce(AuthorizationCustomizer) -> AuthorizationCustomizer<NewP, NewE, NewH>,
    {
        SecurityLayerBuilder {
            authenticator: self.authenticator,
            authorization: AuthorizationConfiguration::Configure(customize(
                AuthorizationCustomizer::default(),
            )),
        }
    }
}

impl<A, P, E, H> SecurityLayerBuilder<A, P, E, H>
where
    A: RequestAuthenticator + 'static,
    P: AuthorizationProvider<Authentication = A::Authentication>,
    E: AuthenticationEntryPoint,
    H: AuthorizationFailureHandler<P::Error>,
{
    /// Builds authentication followed by authorization.
    pub fn build(self) -> SecurityServiceBuilder<A, P, H, E> {
        let authentication = AuthenticationLayer::new(self.authenticator);
        let authorization = match self.authorization {
            AuthorizationConfiguration::Ready(layer) => layer,
            AuthorizationConfiguration::Configure(configuration) => {
                AuthorizationLayer::builder(configuration.provider)
                    .authentication_entry_point(configuration.authentication_entry_point)
                    .failure_handler(configuration.failure_handler)
                    .build()
            }
        };

        ServiceBuilder::new()
            .layer(authentication)
            .layer(authorization)
    }
}

/// Tower builder containing the authentication and authorization layers.
/// `A` is the authenticator type, whose identity is `A::Authentication`.
pub type SecurityServiceBuilder<A, P, H, E> =
    ServiceBuilder<Stack<AuthorizationLayer<P, H, E>, Stack<AuthenticationLayer<A>, Identity>>>;

#[cfg(test)]
#[path = "security_builder_tests.rs"]
mod tests;

use tower::ServiceBuilder;
use tower_layer::{Identity, Stack};

use crate::{
    authentication::{
        AuthenticationLayer, DelegatingRequestAuthenticator, DelegatingRequestAuthenticatorBuilder,
    },
    authorization::{
        AuthenticationEntryPoint, AuthorizationContextMapper, AuthorizationFailureHandler,
        AuthorizationLayer, AuthorizationProvider, DefaultAuthenticationEntryPoint,
        DefaultAuthorizationFailureHandler,
    },
};

/// Configures the authorization part of a security layer.
pub struct AuthorizationCustomizer<
    P = (),
    F = (),
    E = DefaultAuthenticationEntryPoint,
    H = DefaultAuthorizationFailureHandler,
> {
    provider: P,
    context: F,
    authentication_entry_point: E,
    failure_handler: H,
}

impl Default for AuthorizationCustomizer {
    fn default() -> Self {
        Self {
            provider: (),
            context: (),
            authentication_entry_point: DefaultAuthenticationEntryPoint,
            failure_handler: DefaultAuthorizationFailureHandler,
        }
    }
}

impl<E, H> AuthorizationCustomizer<(), (), E, H> {
    /// Selects the authorization provider and request context mapper.
    pub fn authorize_with<P, F>(
        self,
        provider: P,
        context: F,
    ) -> AuthorizationCustomizer<P, F, E, H> {
        AuthorizationCustomizer {
            provider,
            context,
            authentication_entry_point: self.authentication_entry_point,
            failure_handler: self.failure_handler,
        }
    }
}

impl<P, F, E, H> AuthorizationCustomizer<P, F, E, H> {
    /// Replaces the default authentication entry point.
    pub fn authentication_entry_point<NewEntryPoint>(
        self,
        authentication_entry_point: NewEntryPoint,
    ) -> AuthorizationCustomizer<P, F, NewEntryPoint, H> {
        AuthorizationCustomizer {
            provider: self.provider,
            context: self.context,
            authentication_entry_point,
            failure_handler: self.failure_handler,
        }
    }

    /// Replaces the default authorization failure handler.
    pub fn failure_handler<NewHandler>(
        self,
        failure_handler: NewHandler,
    ) -> AuthorizationCustomizer<P, F, E, NewHandler> {
        AuthorizationCustomizer {
            provider: self.provider,
            context: self.context,
            authentication_entry_point: self.authentication_entry_point,
            failure_handler,
        }
    }
}

enum AuthorizationConfiguration<P, F, E, H> {
    Configure(AuthorizationCustomizer<P, F, E, H>),
    Ready(AuthorizationLayer<P, F, H, E>),
}

/// Builds authentication and authorization middleware.
pub struct SecurityLayerBuilder<
    A = (),
    P = (),
    F = (),
    E = DefaultAuthenticationEntryPoint,
    H = DefaultAuthorizationFailureHandler,
> {
    authenticators: DelegatingRequestAuthenticatorBuilder<A>,
    authorization: AuthorizationConfiguration<P, F, E, H>,
}

impl SecurityLayerBuilder {
    /// Starts building security middleware.
    pub fn builder() -> Self {
        Self {
            authenticators: DelegatingRequestAuthenticator::builder(),
            authorization: AuthorizationConfiguration::Configure(AuthorizationCustomizer::default()),
        }
    }

    /// Configures the ordered authentication chain.
    pub fn authenticators<A, C>(self, customize: C) -> SecurityLayerBuilder<A>
    where
        A: Clone + Send + Sync + 'static,
        C: FnOnce(
            DelegatingRequestAuthenticatorBuilder<A>,
        ) -> DelegatingRequestAuthenticatorBuilder<A>,
    {
        SecurityLayerBuilder {
            authenticators: customize(DelegatingRequestAuthenticator::builder()),
            authorization: self.authorization,
        }
    }
}

impl<A> SecurityLayerBuilder<A> {
    /// Uses an already configured authorization layer, preserving its handlers and provider.
    pub fn authorization_layer<P, F, H, E>(
        self,
        layer: AuthorizationLayer<P, F, H, E>,
    ) -> SecurityLayerBuilder<A, P, F, E, H>
    where
        P: AuthorizationProvider<Authentication = A>,
    {
        SecurityLayerBuilder {
            authenticators: self.authenticators,
            authorization: AuthorizationConfiguration::Ready(layer),
        }
    }

    /// Configures authorization.
    pub fn authorization<NewP, NewF, NewE, NewH, C>(
        self,
        customize: C,
    ) -> SecurityLayerBuilder<A, NewP, NewF, NewE, NewH>
    where
        C: FnOnce(AuthorizationCustomizer) -> AuthorizationCustomizer<NewP, NewF, NewE, NewH>,
    {
        SecurityLayerBuilder {
            authenticators: self.authenticators,
            authorization: AuthorizationConfiguration::Configure(customize(
                AuthorizationCustomizer::default(),
            )),
        }
    }
}

impl<A, P, F, E, H> SecurityLayerBuilder<A, P, F, E, H>
where
    A: Clone + Send + Sync + 'static,
    P: AuthorizationProvider<Authentication = A>,
    F: AuthorizationContextMapper<P::Context>,
    E: AuthenticationEntryPoint,
    H: AuthorizationFailureHandler<P::Error>,
{
    /// Builds authentication followed by authorization.
    pub fn build(self) -> SecurityServiceBuilder<A, P, F, H, E> {
        let authentication = AuthenticationLayer::new(self.authenticators.build());
        let authorization = match self.authorization {
            AuthorizationConfiguration::Ready(layer) => layer,
            AuthorizationConfiguration::Configure(configuration) => {
                AuthorizationLayer::builder(configuration.provider, configuration.context)
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
pub type SecurityServiceBuilder<A, P, F, H, E> = ServiceBuilder<
    Stack<
        AuthorizationLayer<P, F, H, E>,
        Stack<AuthenticationLayer<DelegatingRequestAuthenticator<A>>, Identity>,
    >,
>;

#[cfg(test)]
#[path = "security_builder_tests.rs"]
mod tests;

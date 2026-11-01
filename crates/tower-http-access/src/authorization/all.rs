use super::{AuthorizationDecision, AuthorizationProvider};
use futures_util::future::BoxFuture;
use http::request::Parts;

/// Error returned by a provider in an all-of authorization chain.
///
/// The original provider error is available through [`std::error::Error::source`].
#[derive(Debug, thiserror::Error)]
#[error("authorization provider failed: {source}")]
pub struct AllAuthorizationError {
    #[source]
    source: Box<dyn std::error::Error + Send + Sync>,
}

/// Building an all-of authorization chain requires at least one provider.
#[derive(Debug, thiserror::Error)]
#[error("at least one authorization provider is required")]
pub struct EmptyAuthorizationProviders;

type Provider<A> =
    Box<dyn AuthorizationProvider<Authentication = A, Error = AllAuthorizationError>>;

struct ProviderAdapter<P>(P);

impl<P> AuthorizationProvider for ProviderAdapter<P>
where
    P: AuthorizationProvider,
    P::Error: 'static,
{
    type Authentication = P::Authentication;
    type Error = AllAuthorizationError;

    fn authorize<'a>(
        &'a self,
        authentication: Option<&'a Self::Authentication>,
        request: &'a Parts,
    ) -> BoxFuture<'a, Result<AuthorizationDecision, Self::Error>> {
        Box::pin(async move {
            self.0
                .authorize(authentication, request)
                .await
                .map_err(|error| AllAuthorizationError {
                    source: Box::new(error),
                })
        })
    }
}

/// Allows a request only when every configured provider allows it.
///
/// Providers run sequentially in registration order, receiving the same optional identity and
/// request parts. The first denial or error is returned immediately; later providers are skipped.
/// Anonymous requests are passed to each provider as `None`, so each provider determines whether
/// authentication is required. Providers may have different error types; errors are wrapped in
/// [`AllAuthorizationError`] with their original source preserved.
///
/// ```
/// use tower_http_access::authorization::{
///     AllAuthorizationProvider, AuthenticatedAuthorizationProvider, AuthorizationLayer,
///     AuthorizationProviderExt,
/// };
///
/// struct AppUser { id: u64 }
///
/// let provider = AllAuthorizationProvider::<AppUser>::builder()
///     .with(AuthenticatedAuthorizationProvider::<AppUser>::new())
///     // Adapt another provider that expects a different identity type.
///     .with(AuthenticatedAuthorizationProvider::<String>::new()
///         .map(|user: &AppUser| user.id.to_string()))
///     .build()?;
/// let layer = AuthorizationLayer::builder(provider).build();
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct AllAuthorizationProvider<A> {
    providers: Vec<Provider<A>>,
}

impl<A> AllAuthorizationProvider<A> {
    /// Start configuring an all-of chain. Building an empty chain returns an error.
    pub fn builder() -> AllAuthorizationProviderBuilder<A> {
        AllAuthorizationProviderBuilder {
            providers: Vec::new(),
        }
    }
}

/// Collects providers for an [`AllAuthorizationProvider`].
pub struct AllAuthorizationProviderBuilder<A> {
    providers: Vec<Provider<A>>,
}

impl<A> AllAuthorizationProviderBuilder<A> {
    /// Append a provider. All providers must accept the same identity type.
    pub fn with<P>(mut self, provider: P) -> Self
    where
        P: AuthorizationProvider<Authentication = A> + 'static,
        P::Error: 'static,
    {
        self.providers.push(Box::new(ProviderAdapter(provider)));
        self
    }

    /// Build a nonempty chain, rejecting accidental empty configurations.
    pub fn build(self) -> Result<AllAuthorizationProvider<A>, EmptyAuthorizationProviders> {
        if self.providers.is_empty() {
            return Err(EmptyAuthorizationProviders);
        }
        Ok(AllAuthorizationProvider {
            providers: self.providers,
        })
    }
}

impl<A: Send + Sync> AuthorizationProvider for AllAuthorizationProvider<A> {
    type Authentication = A;
    type Error = AllAuthorizationError;

    fn authorize<'a>(
        &'a self,
        authentication: Option<&'a A>,
        request: &'a Parts,
    ) -> BoxFuture<'a, Result<AuthorizationDecision, Self::Error>> {
        Box::pin(async move {
            for provider in &self.providers {
                match provider.authorize(authentication, request).await? {
                    AuthorizationDecision::Allow => (),
                    denial => return Ok(denial),
                }
            }
            Ok(AuthorizationDecision::Allow)
        })
    }
}

#[cfg(test)]
#[path = "all_tests.rs"]
mod tests;

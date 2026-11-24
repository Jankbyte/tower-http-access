use std::{pin::Pin, sync::Arc};
use user_password_auth::{Credentials, UsernamePasswordAuthenticationProvider};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let provider = SimpleProvider::new("alex", "alex123");

    let credentials = Credentials::new("alex", "alex123");
    let result = provider.authenticate(&credentials).await;
    assert_eq!("alex", result.unwrap().unwrap().0.as_str());

    let credentials = Credentials::new("alex", "wrongpassword");
    let result = provider.authenticate(&credentials).await;
    assert_eq!(Ok(None), result);
}

#[derive(Debug, PartialEq)]
struct Principal(String);

struct SimpleProvider(String, String);

impl SimpleProvider {
    fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self(username.into(), password.into())
    }
}

impl UsernamePasswordAuthenticationProvider for SimpleProvider {
    type Authentication = Arc<Principal>; // wrap with Arc for cheap clone
    type Error = std::convert::Infallible;

    fn authenticate<'a>(
        &'a self,
        credentials: &'a Credentials,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Self::Authentication>, Self::Error>> + Send + 'a>>
    {
        Box::pin(async {
            if credentials.username == self.0.as_str() && credentials.password == self.1.as_str() {
                Ok(Some(Arc::new(Principal(credentials.username.to_owned()))))
            } else {
                Ok(None)
            }
        })
    }
}

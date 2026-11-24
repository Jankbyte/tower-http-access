use tower_http_access_authorizers::authorities::HasAuthorities;
use user_password_auth::{Authority, UserDetail};

#[derive(Clone)]
pub(crate) struct Principal(pub(crate) UserDetail);

impl From<UserDetail> for Principal {
    fn from(user: UserDetail) -> Self {
        Self(user)
    }
}

impl std::ops::Deref for Principal {
    type Target = UserDetail;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl HasAuthorities for Principal {
    fn has_authority(&self, authority: &str) -> bool {
        self.authorities.contains(&Authority::new(authority))
    }
}

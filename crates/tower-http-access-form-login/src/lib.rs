#![doc = include_str!("../README.md")]

mod error;
pub use error::{FormLoginError, InvalidRedirectPath};

mod handlers;
pub use handlers::{
    DefaultFailureHandler, DefaultSuccessHandler, FailureHandler, RedirectSuccessHandler,
    SuccessHandler,
};

mod tower_layer;
pub use tower_layer::{FormLoginLayer, FormLoginService};

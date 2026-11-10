//! Framework-independent form login middleware.

mod error;
pub use error::FormLoginError;

mod handlers;
pub use handlers::{
    DefaultFailureHandler, DefaultSuccessHandler, FailureHandler, RedirectSuccessHandler,
    SuccessHandler,
};

mod session_set_success_handler;
pub use session_set_success_handler::SessionSetSuccessHandler;

mod tower_layer;
pub use tower_layer::{FormLoginLayer, FormLoginService};

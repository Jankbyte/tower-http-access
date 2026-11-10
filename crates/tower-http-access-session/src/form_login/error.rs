/// A rejected form submission or authentication backend failure.
#[derive(Debug)]
pub enum FormLoginError<E> {
    UnsupportedMediaType,
    BodyTooLarge,
    BodyRead,
    InvalidForm,
    InvalidCredentials,
    Backend(E),
}

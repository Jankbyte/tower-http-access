use ::base64::{DecodeError, Engine, engine::general_purpose::STANDARD};
use http::{header::AUTHORIZATION, request::Parts};
use std::{fmt, str::Utf8Error};

#[derive(Clone, Eq, PartialEq)]
pub struct BasicCredentials {
    pub username: String,
    pub password: String,
}

impl fmt::Debug for BasicCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BasicCredentials")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BasicCredentialsError {
    #[error("Basic authorization header is not valid text")]
    InvalidHeader(#[source] http::header::ToStrError),
    #[error("Basic credentials are not valid base64")]
    InvalidBase64(#[source] DecodeError),
    #[error("Basic credentials are not valid UTF-8")]
    InvalidUtf8(#[source] Utf8Error),
    #[error("Basic credentials must contain a username and password")]
    MissingSeparator,
}

/// Extract credentials from HTTP-request headers.
///
/// If request does not have `Authorization` header or header value does not starts with `Basic` schema,
/// so [`Result`] with [`Option::None`] will return.
pub fn extract_credentials(
    parts: &Parts,
) -> Result<Option<BasicCredentials>, BasicCredentialsError> {
    let Some(header) = parts.headers.get(AUTHORIZATION) else {
        return Ok(None);
    };
    let header = header
        .to_str()
        .map_err(BasicCredentialsError::InvalidHeader)?
        .trim();
    let (scheme, encoded) = match header.split_once(char::is_whitespace) {
        Some(parts) => parts,
        None if header.eq_ignore_ascii_case("Basic") => (header, ""),
        None => return Ok(None),
    };
    if !scheme.eq_ignore_ascii_case("Basic") {
        return Ok(None);
    }

    let decoded = STANDARD
        .decode(encoded.trim())
        .map_err(BasicCredentialsError::InvalidBase64)?;
    let decoded = std::str::from_utf8(&decoded).map_err(BasicCredentialsError::InvalidUtf8)?;
    let (username, password) = decoded
        .split_once(':')
        .ok_or(BasicCredentialsError::MissingSeparator)?;

    Ok(Some(BasicCredentials {
        username: username.to_owned(),
        password: password.to_owned(),
    }))
}

#[cfg(test)]
#[path = "base64_tests.rs"]
mod tests;

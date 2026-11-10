use http::{header, request::Parts};
use mime::Mime;

use crate::core::RequestMatcher;

/// An invalid media type encountered while configuring a matcher.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid media type: {0}")]
pub struct InvalidMediaType(pub String);

/// Matches media ranges from the request's `Accept` headers.
///
/// Inspired by Spring Security's `MediaTypeRequestMatcher`, with header parsing
/// directly in the matcher and no content-negotiation strategy. `Content-Type`,
/// URL extensions, and query parameters are not consulted.
///
/// By default, any compatible pair of configured and requested media types matches.
/// Compatibility is symmetric, ignores parameters, and supports `*/*`, `text/*`,
/// and suffix wildcards such as `application/*+json`. A missing or empty `Accept`
/// is treated as `*/*`. Invalid headers cause the whole request to not match,
/// even if another entry is valid. Multiple header lines are considered together.
///
/// Like Spring's matcher, this selects a policy rather than negotiating a response:
/// quality values do not rank entries or exclude `q=0`. All entries are checked,
/// including in exact mode; header order does not change the result.
/// Headers are client-controlled and do not establish authentication.
///
/// ```
/// use http::Request;
/// use http_request_matcher::MediaTypeRequestMatcher;
/// use http_request_matcher::RequestMatcher;
///
/// let matcher = MediaTypeRequestMatcher::new(["text/html"])?
///     .with_ignored_media_types(["*/*"])?;
/// let (parts, _) = Request::builder()
///     .header("accept", "text/html, application/json;q=0.8, */*;q=0.5")
///     .body(())?
///     .into_parts();
/// assert!(matcher.matches(&parts));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Debug)]
pub struct MediaTypeRequestMatcher {
    matching: Vec<Mime>,
    ignored: Vec<Mime>,
    use_equals: bool,
}

impl MediaTypeRequestMatcher {
    /// Parse the media types once during configuration. An empty collection
    /// creates a matcher that never matches.
    pub fn new(
        media_types: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Result<Self, InvalidMediaType> {
        Ok(Self {
            matching: parse_configuration(media_types)?,
            ignored: Vec::new(),
            use_equals: false,
        })
    }

    /// Use exact equality, including parameters, instead of wildcard compatibility.
    /// Parameter order and quoting do not matter. Types, subtypes, parameter names,
    /// and charset values are case-insensitive; other parameter values are sensitive.
    /// A requested `application/json;q=0.8` differs from configured `application/json`.
    /// Calling this again replaces the previous setting.
    #[must_use]
    pub fn with_use_equals(mut self, use_equals: bool) -> Self {
        self.use_equals = use_equals;
        self
    }

    /// Replace the set of ignored media types.
    ///
    /// Following Spring, a requested range is skipped if it *includes* an ignored
    /// type, ignoring parameters. Ignoring `*/*` skips requested `*/*`, including
    /// the fallback for a missing `Accept`, while preserving concrete ranges.
    /// Ignoring `application/json` also skips requested `application/*` and `*/*`;
    /// ignoring `application/*` does not skip requested `application/json`.
    pub fn with_ignored_media_types(
        mut self,
        media_types: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Result<Self, InvalidMediaType> {
        self.ignored = parse_configuration(media_types)?;
        Ok(self)
    }

    fn matches_media_type(&self, requested: &Mime) -> bool {
        !self
            .ignored
            .iter()
            .any(|ignored| includes(requested, ignored))
            && self.matching.iter().any(|matching| {
                if self.use_equals {
                    equals(matching, requested)
                } else {
                    compatible(matching, requested)
                }
            })
    }
}

impl RequestMatcher for MediaTypeRequestMatcher {
    fn matches(&self, request: &Parts) -> bool {
        let mut found = false;
        let mut matched = false;
        for value in request.headers.get_all(header::ACCEPT) {
            let Ok(value) = value.to_str() else {
                return false;
            };
            // Commas in quoted parameter values are not list separators.
            let mut quoted = false;
            let mut escaped = false;
            for range in value.split(|ch| {
                if escaped {
                    escaped = false;
                } else if quoted && ch == '\\' {
                    escaped = true;
                } else if ch == '"' {
                    quoted = !quoted;
                } else if ch == ',' && !quoted {
                    return true;
                }
                false
            }) {
                let range = range.trim();
                if range.is_empty() {
                    continue;
                }
                let Some(media_type) = parse_media_type(range) else {
                    return false;
                };
                found = true;
                matched |= self.matches_media_type(&media_type);
            }
        }
        if found {
            matched
        } else {
            self.matches_media_type(&mime::STAR_STAR)
        }
    }
}

fn parse_configuration(
    types: impl IntoIterator<Item = impl AsRef<str>>,
) -> Result<Vec<Mime>, InvalidMediaType> {
    types
        .into_iter()
        .map(|value| {
            let value = value.as_ref();
            parse_media_type(value.trim()).ok_or_else(|| InvalidMediaType(value.to_owned()))
        })
        .collect()
}

fn parse_media_type(value: &str) -> Option<Mime> {
    // Mime expects the semicolon directly after the subtype, whereas Accept can
    // contain optional whitespace before it. Preserve all parameter contents.
    let normalized;
    let value = if let Some((essence, parameters)) = value.split_once(';') {
        if essence != essence.trim_end() {
            normalized = format!("{};{parameters}", essence.trim_end());
            normalized.as_str()
        } else {
            value
        }
    } else {
        value
    };
    let media_type = value.parse::<Mime>().ok()?;
    if media_type.subtype().as_str().is_empty() {
        return None;
    }
    if media_type.type_() == mime::STAR && media_type.essence_str() != "*/*" {
        return None;
    }
    // Mime validates the syntax of parameters, but not HTTP quality values.
    for (name, value) in media_type.params() {
        if name == "q" {
            let quality = value.as_str().parse::<f64>().ok()?;
            if !(0.0..=1.0).contains(&quality) {
                return None;
            }
        }
    }
    Some(media_type)
}

fn compatible(left: &Mime, right: &Mime) -> bool {
    if left.type_() == mime::STAR || right.type_() == mime::STAR {
        return true;
    }
    if left.type_() != right.type_() {
        return false;
    }
    if left.essence_str() == right.essence_str()
        || left.subtype() == mime::STAR && left.suffix().is_none()
        || right.subtype() == mime::STAR && right.suffix().is_none()
    {
        return true;
    }
    suffix_compatible(left, right) || suffix_compatible(right, left)
}

fn suffix_compatible(wildcard: &Mime, other: &Mime) -> bool {
    wildcard.subtype() == mime::STAR
        && wildcard.suffix().is_some_and(|suffix| {
            other.suffix() == Some(suffix) || other.suffix().is_none() && other.subtype() == suffix
        })
}

fn includes(range: &Mime, other: &Mime) -> bool {
    range.type_() == mime::STAR
        || range.type_() == other.type_()
            && (range.essence_str() == other.essence_str()
                || range.subtype() == mime::STAR
                    && (range.suffix().is_none() || range.suffix() == other.suffix()))
}

fn equals(left: &Mime, right: &Mime) -> bool {
    // Compare as a parameter map, independent of the source order.
    left.essence_str() == right.essence_str()
        && left.params().count() == right.params().count()
        && left.params().all(|(name, value)| {
            right.get_param(name).is_some_and(|other| {
                if name == mime::CHARSET {
                    value.as_str().eq_ignore_ascii_case(other.as_str())
                } else {
                    value.as_str() == other.as_str()
                }
            })
        })
}

#[cfg(test)]
#[path = "media_type_tests.rs"]
mod tests;

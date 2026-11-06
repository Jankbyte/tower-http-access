use super::*;

fn request(accept: &[&str]) -> Parts {
    let mut builder = http::Request::builder();
    for value in accept {
        builder = builder.header(header::ACCEPT, *value);
    }
    builder.body(()).unwrap().into_parts().0
}

#[test]
fn compatibility_handles_headers_parameters_and_wildcards() {
    let matcher = MediaTypeRequestMatcher::new(["application/json", "text/html"]).unwrap();
    for (accept, expected) in [
        (vec![], true),
        (vec![""], true),
        (vec![" , "], true),
        (vec!["application/json"], true),
        (vec![" Text/HTML ; charset=utf-8"], true),
        (vec!["application/json;q=0"], true),
        (vec!["application/json;q=0.1234"], true),
        (vec!["application/*"], true),
        (vec!["text/*"], true),
        (vec!["*/*"], true),
        (vec!["application/xml, text/html;q=0.8"], true),
        (vec!["application/xml", "text/html"], true),
        (vec!["application/xml"], false),
        (vec!["image/*"], false),
        (vec!["application/problem+json"], false),
        (vec!["application/json;profile=\"a,b;c\""], true),
    ] {
        assert_eq!(matcher.matches(&request(&accept)), expected, "{accept:?}");
    }
    let mut parts = request(&[]);
    parts
        .headers
        .insert(header::CONTENT_TYPE, "text/html".parse().unwrap());
    // Only Accept is considered; Content-Type cannot override a mismatch.
    parts
        .headers
        .insert(header::ACCEPT, "image/png".parse().unwrap());
    assert!(!matcher.matches(&parts));
    assert!(
        !MediaTypeRequestMatcher::new([] as [&str; 0])
            .unwrap()
            .matches(&request(&[]))
    );
}

#[test]
fn suffix_wildcard_compatibility_is_symmetric() {
    for (left, right, expected) in [
        ("application/*+json", "application/problem+json", true),
        ("application/*+json", "application/json", true),
        ("application/*+json", "application/*", true),
        ("application/*+json", "application/*+json", true),
        ("application/*+json", "application/*+xml", false),
        ("application/*+json", "text/problem+json", false),
        ("application/*+json", "application/xml", false),
        ("application/json", "application/problem+json", false),
    ] {
        assert_eq!(
            MediaTypeRequestMatcher::new([left])
                .unwrap()
                .matches(&request(&[right])),
            expected,
            "{left} versus {right}",
        );
        assert_eq!(
            MediaTypeRequestMatcher::new([right])
                .unwrap()
                .matches(&request(&[left])),
            expected,
            "{right} versus {left}",
        );
    }
}

#[test]
fn exact_mode_checks_every_entry_and_compares_parameter_maps() {
    let matcher = MediaTypeRequestMatcher::new(["application/json", "text/html"])
        .unwrap()
        .with_use_equals(true);
    for (accept, expected) in [
        (vec![], false),
        (vec!["application/json"], true),
        (vec!["APPLICATION/JSON"], true),
        (vec!["application/*"], false),
        (vec!["*/*"], false),
        (vec!["application/json;q=1"], false),
        (vec!["application/json;charset=utf-8"], false),
        (vec!["image/png, text/html"], true),
        (vec!["text/html, image/png"], true),
        (vec!["image/png", "application/json"], true),
    ] {
        assert_eq!(matcher.matches(&request(&accept)), expected, "{accept:?}");
    }
    let parameterized = MediaTypeRequestMatcher::new(["text/html;charset=utf-8;level=One"])
        .unwrap()
        .with_use_equals(true);
    for (accept, expected) in [
        ("TEXT/HTML;LEVEL=One;CHARSET=UTF-8", true),
        ("text/html;level=\"One\";charset=\"utf-8\"", true),
        ("text/html;level=one;charset=utf-8", false),
        ("text/html;level=Two;charset=utf-8", false),
        ("text/html;level=One;charset=ascii", false),
        ("text/html;level=One", false),
    ] {
        assert_eq!(
            parameterized.matches(&request(&[accept])),
            expected,
            "{accept}"
        );
    }
    assert!(matcher.with_use_equals(false).matches(&request(&["*/*"])));
    assert!(
        MediaTypeRequestMatcher::new(["*/*"])
            .unwrap()
            .with_use_equals(true)
            .matches(&request(&[]))
    );
}

#[test]
fn ignored_media_types_follow_requested_range_inclusion() {
    let matcher = MediaTypeRequestMatcher::new(["application/json", "text/html"])
        .unwrap()
        .with_ignored_media_types(["*/*"])
        .unwrap();
    for (accept, expected) in [
        (vec![], false),
        (vec!["*/*;q=0.8"], false),
        (vec!["text/*"], true),
        (vec!["application/json"], true),
        (vec!["*/*, text/html"], true),
        (vec!["*/*", "application/json;q=0"], true),
    ] {
        assert_eq!(matcher.matches(&request(&accept)), expected, "{accept:?}");
    }
    let matcher = matcher
        .with_ignored_media_types(["application/json;charset=utf-8"])
        .unwrap();
    for (accept, expected) in [
        ("*/*", false),
        ("application/*", false),
        ("application/json", false),
        ("text/html", true),
        ("text/*", true),
        ("application/json, text/html", true),
    ] {
        assert_eq!(matcher.matches(&request(&[accept])), expected, "{accept}");
    }
    assert!(
        matcher
            .with_ignored_media_types([] as [&str; 0])
            .unwrap()
            .matches(&request(&["application/json"]))
    );
    let matcher = MediaTypeRequestMatcher::new(["application/*"])
        .unwrap()
        .with_ignored_media_types(["application/*"])
        .unwrap();
    assert!(matcher.matches(&request(&["application/json"])));
    let matcher = MediaTypeRequestMatcher::new(["application/*"])
        .unwrap()
        .with_ignored_media_types(["application/problem+json"])
        .unwrap();
    assert!(!matcher.matches(&request(&["application/*+json"])));
    assert!(matcher.matches(&request(&["application/json"])));
}

#[test]
fn malformed_accept_fails_even_after_a_matching_entry() {
    let matcher = MediaTypeRequestMatcher::new(["text/html"]).unwrap();
    for invalid in [
        "invalid",
        "text/",
        "*/html",
        "text/html;q=nope",
        "text/html;q=NaN",
        "text/html;q=inf",
        "text/html;q=1.1",
        "text/html;q=-0.1",
        "text/html;profile=\"unclosed",
        "text/html;profile=\"a,b\", bad",
    ] {
        for values in [
            vec![invalid],
            vec!["text/html", invalid],
            vec![invalid, "text/html"],
        ] {
            assert!(!matcher.matches(&request(&values)), "{values:?}");
        }
        assert!(
            !matcher.matches(&request(&[&format!("text/html, {invalid}")])),
            "{invalid}"
        );
    }
    let mut parts = request(&["text/html"]);
    parts.headers.append(
        header::ACCEPT,
        http::HeaderValue::from_bytes(&[0xff]).unwrap(),
    );
    assert!(!matcher.matches(&parts));
}

#[test]
fn invalid_configuration_is_rejected_before_matching() {
    for value in [
        "",
        "json",
        "*/json",
        "application/json, text/html",
        "text/html;q=2",
    ] {
        let error = MediaTypeRequestMatcher::new([value]).unwrap_err();
        assert_eq!(error.0, value);
        assert_eq!(error.to_string(), format!("invalid media type: {value}"));
        assert!(
            MediaTypeRequestMatcher::new(["text/html"])
                .unwrap()
                .with_ignored_media_types([value])
                .is_err()
        );
    }
}

use axum::{Router, response::Redirect, routing::get};
use axum::{
    body::Body,
    http::{StatusCode, Uri, header},
    response::IntoResponse,
};
use include_dir::{Dir, include_dir};

const UI_PREFIX: &str = "/ui";
static FRONTEND: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/../react-frontend/dist");

pub fn router() -> Router {
    Router::new()
        .route("/", get(|| async { Redirect::temporary(UI_PREFIX) }))
        .route(
            UI_PREFIX,
            get(|| async { Redirect::permanent(format!("{UI_PREFIX}/").as_str()) }),
        )
        .nest(
            format!("{UI_PREFIX}/").as_str(),
            Router::new()
                .route("/", get(serve_frontend))
                .route("/{*path}", get(serve_frontend)),
        )
}

async fn serve_frontend(uri: Uri) -> Result<impl IntoResponse, StatusCode> {
    // Axum strips the /ui prefix when entering the nested router.
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };
    let asset = FRONTEND
        .get_file(path)
        .map(|file| (path, file))
        .or_else(|| {
            // Client-side routes get the application shell; missing assets get 404.
            if !path.starts_with("assets/") && !path.contains('.') {
                FRONTEND
                    .get_file("index.html")
                    .map(|file| ("index.html", file))
            } else {
                None
            }
        });

    let (path, file) = asset.ok_or(StatusCode::NOT_FOUND)?;
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    Ok((
        [(header::CONTENT_TYPE, mime.to_string())],
        Body::from(file.contents()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::to_bytes, http::Request};
    use tower::ServiceExt;

    #[tokio::test]
    async fn serves_ui_root_assets_and_client_routes() {
        for path in ["/ui/", "/ui/index.html", "/ui/dashboard"] {
            let response = router()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            assert_eq!(response.headers()[header::CONTENT_TYPE], "text/html");
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            assert_eq!(
                body.as_ref(),
                FRONTEND.get_file("index.html").unwrap().contents()
            );
        }

        for (path, status) in [
            ("/ui", StatusCode::PERMANENT_REDIRECT),
            ("/ui/favicon.svg", StatusCode::OK),
            ("/ui/assets/missing.js", StatusCode::NOT_FOUND),
            ("/api/missing", StatusCode::NOT_FOUND),
            ("/", StatusCode::TEMPORARY_REDIRECT),
        ] {
            let response = router()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), status, "{path}");
            if path == "/ui" {
                assert_eq!(response.headers()[header::LOCATION], "/ui/");
            } else if path == "/" {
                assert_eq!(response.headers()[header::LOCATION], UI_PREFIX);
            }
        }
    }
}

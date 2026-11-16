# axum-server usage

This example demonstrate usage `tower-http-access` abstractions with `tower/hyper`-based `axum-server`.

Usage:
```bash
cargo run --bin axum-server-usage
curl -v http://127.0.0.1:3000/v1/auth/info
curl -u 'user:user123' -v http://127.0.0.1:3000/v1/auth/info
```

# axum-server usage

This example demonstrate usage `tower-http-access` abstractions with [hyper](https://docs.rs/hyper/latest/hyper/) and [tower](https://docs.rs/tower/latest/tower/index.html), where wrapper is [axum-server](https://docs.rs/axum-server/latest/axum_server/).

Usage:
```bash
cargo run --bin axum-server-usage
curl -v http://127.0.0.1:3000/v1/auth/info
curl -u 'user:user123' -v http://127.0.0.1:3000/v1/auth/info
```

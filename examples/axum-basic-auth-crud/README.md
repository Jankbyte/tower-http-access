# Simple basic CRUD

The simple implementation of create/read/update/delete (CRUD) with `axum` and `tower-http-access` abstractions.

Run application:
```bash
cargo run axum-basic-auth-crud
```

Test requests:
```bash
curl -v http://127.0.0.1:3000/v1/notes/1
curl -u 'alex:alex123' -v http://127.0.0.1:3000/v1/notes/1
```

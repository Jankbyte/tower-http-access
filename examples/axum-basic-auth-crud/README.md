# Simple basic CRUD

The simple implementation of create/read/update/delete (CRUD) with `axum` and `tower-http-access` abstractions.

Run application:
```bash
cargo run axum-basic-auth-crud
```

Test requests:
```bash
curl -v http://127.0.0.1:3000/v1/auth/info
curl -u 'reader:reader123' -v http://127.0.0.1:3000/v1/auth/info
# Public access (200)
curl -v http://127.0.0.1:3000/v1/notes/1
# Read note (200)
curl -u 'reader:reader123' -v http://127.0.0.1:3000/v1/notes/2
# Create note (200)
curl \
 -X POST \
 -H "Content-Type: application/json" \
 --data '{"title": "Demo", "content": "demo demo"}' \
 -u 'creator:creator123' \
 -v 'http://127.0.0.1:3000/v1/notes'
# Delete note (200)
curl -X DELETE -u 'remover:remover123' -v http://127.0.0.1:3000/v1/notes/2
# Replace note (200)
curl \
 -X PUT \
 -H "Content-Type: application/json" \
 --data '{"title": "Demo replaced", "content": "demo demo replaced"}' \
 -u 'replacer:replacer123' \
 -v 'http://127.0.0.1:3000/v1/notes/2'
```

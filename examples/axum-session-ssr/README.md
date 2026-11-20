# Axum - Session server side rendering

This example is shows how to use `tower-http-access` for server side rendering applications, where
HTML page fully generated on server side.

Starting:
```bash
cargo run --bin axum-session-ssr
```
The open [link](http://localhost:3000).

After login, visit `/me` to see the account page and its logout form.
Logout submits `POST /auth/logout` with the hidden CSRF token, flushes the session
(including its stored CSRF token), and redirects to `/auth/login`. The session
middleware expires the browser's session cookie. GET requests do not log users out.

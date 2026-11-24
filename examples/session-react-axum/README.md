# Axum + API + React session example

This is complex example that demonstrate usage of `tower-http-access` with serving frontend session and API together.

## Development

Start the server in one terminal:

```bash
cargo run --bin axum-react-session-backend
```

Start the client in another terminal:

```bash
npm --prefix examples/session-react-axum/react-frontend ci
npm --prefix examples/session-react-axum/react-frontend run dev
```

Open <https://localhost:5173/ui/> and accept the local self-signed certificate.
Vite provides hot reload and proxies API requests to `127.0.0.1:3001`.
Log in with `alex` / `alex123` or `max` / `max123`.

## Build a single binary

Build the client first, then the server:

```bash
npm --prefix examples/session-react-axum/react-frontend ci
npm --prefix examples/session-react-axum/react-frontend run build
cargo build --release --bin axum-react-session-backend
```

Run it:

```bash
./target/release/axum-react-session-backend
```

The binary embeds the frontend; Node.js and the frontend files are not needed at
runtime. Serve it through an HTTPS reverse proxy pointing to `http://127.0.0.1:3001`
and open `/ui/`. HTTPS is required for the Secure session cookie.

Rebuild both client and server after changing the frontend.

# API accessing

You can access only API with basic credentials:
```bash
curl -v -u "alex:alex123" http://localhost:3001/v1/notes/1
```
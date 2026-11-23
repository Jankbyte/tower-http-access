# Tower http access + Axum + React

This example demonstrate how to use `tower-http-access` with NPM-based frontend and Axum.

# Run and build

## Development

Execute backend:
```bash
cargo run --bin axum-react-session-backend
```

Execute frontend part:
```bash
npm --prefix examples/session-react-axum/react-frontend ci
npm --prefix examples/session-react-axum/react-frontend run dev
```

Vite provides HTTPS, hot reload, and proxies `/v1` requests to the HTTP backend.
Browser-session authentication endpoints use `/v1/ui/auth/login` (POST) and
`/v1/ui/auth/me` (GET). The `/me` request also initializes the CSRF cookie when
needed, including when it returns 401 for an anonymous session.
`npm run dev` also watches TypeScript and oxlint diagnostics, showing errors and
warnings in the terminal and a browser overlay. Fixing an issue updates the
diagnostics automatically. Runtime exceptions still appear in the browser console;
these checks do not catch every runtime failure.

Use the Vite URL ending in `/ui/` (normally <https://localhost:5173/ui/>).
The basic SSL plugin generates a self-signed certificate; accept the browser's
certificate warning for local development. Session and CSRF cookies stay Secure,
and the CSRF cookie is named `__Host-XSRF-TOKEN` in both development and production.

## Build single executable

Build the frontend before compiling the backend (from the repository root):

```bash
npm --prefix examples/session-react-axum/react-frontend ci
npm --prefix examples/session-react-axum/react-frontend run build
cargo build --release --bin axum-react-session-backend
```

Run the standalone executable:

```bash
./target/release/axum-react-session-backend
```

Expose the executable through an HTTPS reverse proxy forwarding to
`http://127.0.0.1:3001`, then open its HTTPS URL ending in `/ui/`. The backend
itself serves HTTP; browser-facing HTTPS is required for its Secure cookies.

Release builds embed `dist` with `include_dir`; the executable needs neither
Node.js nor the `dist` directory at runtime. Rebuild the frontend and backend to
update embedded assets. Debug builds require the Vite server instead.

This behavior follows `debug_assertions`: profiles with debug assertions enabled
use Vite; profiles with them disabled embed the frontend.

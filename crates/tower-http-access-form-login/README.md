# Tower HTTP Access - Form Login

A form login middleware, that uses `application/x-www-form-urlencoded` content type for authenticate.

This use `http_body::Body<Data = Bytes>` type as payload and `UsernamePasswordAuthenticationProvider` as authentication source.

# Features

This support features:

| Name      | Description     |
|-----------|-----------------|
| `tracing` | Enable tracing. |

# go-django-sessions

Decode and encode Django session data in Go. Use it to share one login between a Django app and a Go service.

[![Go Reference](https://pkg.go.dev/badge/github.com/soccer99/go-django-sessions.svg)](https://pkg.go.dev/github.com/soccer99/go-django-sessions)
[![Test](https://github.com/soccer99/go-django-sessions/actions/workflows/test.yml/badge.svg)](https://github.com/soccer99/go-django-sessions/actions/workflows/test.yml)
[![Django 4.2 | 5.2 | 6.1](https://img.shields.io/badge/Django-4.2%20%7C%205.2%20%7C%206.1-092E20?logo=django&logoColor=white)](https://www.djangoproject.com/download/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- Decodes the `session_data` column of the `django_session` table.
- Encodes session data that Django can read.
- Supports compressed and uncompressed session data.
- Uses only the Go standard library.
- Tests run against Django 4.2, 5.2, and the latest release.

## Installation

```bash
go get github.com/soccer99/go-django-sessions
```

## Decode a session

```go
package main

import (
    "fmt"
    "log"

    sessions "github.com/soccer99/go-django-sessions"
)

func main() {
    // Read this value from the django_session table.
    raw := "your_session_data_here"

    session, err := sessions.DecodeSession(raw, sessions.SessionOptions{
        SecretKey: "your_django_secret_key",
    })
    if err != nil {
        log.Fatalf("decode failed: %v", err)
    }

    fmt.Println(session["_auth_user_id"])
    // Output: 1
}
```

JSON numbers become `float64` values.

## Encode a session

```go
raw, err := sessions.EncodeSession(map[string]any{
    "_auth_user_id":      "1",
    "_auth_user_backend": "django.contrib.auth.backends.ModelBackend",
    "_auth_user_hash":    "...",
}, sessions.SessionOptions{SecretKey: "your_django_secret_key"})
if err != nil {
    log.Fatal(err)
}
// Write raw to the session_data column of the django_session table.
```

The output has the same format as `SessionStore.encode` in Django. Django can read it without changes.

## Options

```go
type SessionOptions struct {
    SecretKey string // The Django SECRET_KEY. If empty, the library reads DJANGO_SECRET_KEY.
    Salt      string // The signing salt. If empty, the library uses the Django default.
}
```

`DecodeSession` returns `sessions.ErrInvalidSignature` when the signature does not match the secret key.

## Middleware examples

- `examples/stdlib.go`: standard library `net/http`. Run with `go run ./examples`.
- `examples/gin.go`: Gin. Run with `go get github.com/gin-gonic/gin && go run examples/gin.go`.
- `examples/fiber.go`: Fiber. Run with `go get github.com/gofiber/fiber/v2 && go run examples/fiber.go`.

## Tests

```bash
go test ./...
```

The Django tests need [uv](https://docs.astral.sh/uv/). They encode data in a real Django install and decode it in Go, and the reverse. They run against Django 4.2, 5.2, and the latest release on PyPI. If `uv` is not installed, the tests skip the Django checks.

## License

MIT

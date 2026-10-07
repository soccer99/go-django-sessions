# go-django-sessions

Decode and encode Django session data in Go, and authenticate database-backed Django logins in Go services. **Decoding alone does not authenticate a user.**

[![Go Reference](https://pkg.go.dev/badge/github.com/soccer99/go-django-sessions.svg)](https://pkg.go.dev/github.com/soccer99/go-django-sessions)
[![Test](https://github.com/soccer99/go-django-sessions/actions/workflows/test.yml/badge.svg)](https://github.com/soccer99/go-django-sessions/actions/workflows/test.yml)
[![Django 4.2 | 5.2 | 6.1](https://img.shields.io/badge/Django-4.2%20%7C%205.2%20%7C%206.1-092E20?logo=django&logoColor=white)](https://www.djangoproject.com/download/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- Decodes the `session_data` column of the `django_session` table.
- Encodes session data that Django can read.
- Creates browser logins with session rotation, atomic PostgreSQL persistence, cookies, and CSRF rotation.
- Supports compressed and uncompressed session data.
- Authenticates current database sessions with expiry, backend/user, and authentication-hash checks.
- Provides `net/http` middleware and examples for Gin, Echo, and Fiber v2/v3.
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

    fmt.Println(session) // Verified session data; not an authenticated identity.
}
```

JSON numbers become `float64` values.

## Encode a session

```go
raw, err := sessions.EncodeSession(map[string]any{
    "_auth_user_id":      "1",
    "_auth_user_backend": "django.contrib.auth.backends.ModelBackend",
    "_auth_user_hash":    sessions.SessionAuthHash(user.Password, secretKey),
}, sessions.SessionOptions{SecretKey: "your_django_secret_key"})
if err != nil {
    log.Fatal(err)
}
// Low-level encoding only. Use LoginManager below to create a browser login.
```

The output has the same format as `SessionStore.encode` in Django. Django can read it without changes.

## Create or end a Django login

Use `LoginManager` after verifying credentials and reading the current user from
Django's database. It computes the auth hash, rotates anonymous session keys while
preserving data, flushes data on user/hash changes, persists the complete row, and
sets the session cookie. It also rotates Django's CSRF secret, either in the CSRF
cookie or in the session when `CSRFUseSessions` is enabled.

```go
// db is a *sql.DB with a registered PostgreSQL driver.
store := sessions.PostgreSQLStore{DB: db}
sessionCookie := sessions.DefaultSessionCookie()
sessionCookie.Secure = true // Match your Django SESSION_COOKIE_* settings.
csrfCookie := sessions.DefaultCSRFCookie()
csrfCookie.Secure = true // Match your Django CSRF_COOKIE_* settings.
logins := sessions.LoginManager{
    Options: sessions.SessionOptions{SecretKey: secretKey},
    Store: store,
    AuthenticationBackends: []string{sessions.ModelBackend},
    SessionCookie: &sessionCookie,
    CSRFCookie: &csrfCookie,
    SessionAge: 14 * 24 * time.Hour, // Match SESSION_COOKIE_AGE.
    ExpireAtBrowserClose: false, // Match SESSION_EXPIRE_AT_BROWSER_CLOSE.
    CSRFUseSessions: false, // Match CSRF_USE_SESSIONS.
    CSRFAge: 31449600 * time.Second, // Match CSRF_COOKIE_AGE.
    AfterLogin: func(ctx context.Context, user *sessions.AuthUser) error {
        // Match Django's default user_logged_in last_login receiver.
        // Adapt this table/column to your actual user model.
        _, err := db.ExecContext(ctx,
            "UPDATE auth_user SET last_login = $1 WHERE id = $2", time.Now(), user.ID)
        return err
    },
}

// In a login handler, after credentials have been verified:
if _, err := logins.Login(w, r, verifiedUser); err != nil {
    http.Error(w, "login unavailable", http.StatusInternalServerError)
    return
}
http.Redirect(w, r, "/", http.StatusSeeOther)

// In a logout handler:
if err := logins.Logout(w, r); err != nil {
    http.Error(w, "logout unavailable", http.StatusInternalServerError)
    return
}
http.Redirect(w, r, "/", http.StatusSeeOther)
```

Cookie names, paths, domains, Secure, HttpOnly, and SameSite must match Django.
The cookie contains a random session key, not the encoded payload. Defaults match
Django: `sessionid`, HttpOnly, `/`, SameSite=Lax, and a 14-day lifetime. Preserved
`_session_expiry` values override that lifetime (seconds, zero for browser-close,
or an RFC3339 datetime). The database expiry still applies to browser-close cookies.

`PostgreSQLStore` locks and compares the old row in a transaction. It inserts new
keys without overwriting collisions, deletes the old row during rotation, and
rejects updates if a concurrent logout or write changed the row. `LoginManager`
retries key collisions and returns `ErrSessionInterrupted` for changed/deleted
sessions. Implement `LoginStore` with the same atomic guarantees for other databases.

Call login/logout before writing response headers and only when the response will
succeed; login does not wrap handlers or save on arbitrary responses. Persistence
failures emit no cookies. `AfterLogin` runs after persistence and before cookies;
if it fails, the row is already saved. Make hooks idempotent and return an error
response. Go cannot emit Python's `user_logged_in` or `user_logged_out` signals:
implement your application's signal effects explicitly (including logout auditing)
or delegate login/logout to Django if those receivers must execute in Python.

These APIs support database sessions, `ModelBackend`, and the default
`AbstractBaseUser` auth hash. Login requires a current active user and already
verified credentials; it does not check passwords. Protect login, logout, and
other unsafe requests with CSRF validation. Rotating a secret does not validate a
request. The implementation signs with the current `SECRET_KEY`; it does not
migrate sessions using `SECRET_KEY_FALLBACKS`.

## Options

```go
type SessionOptions struct {
    SecretKey string // The Django SECRET_KEY. If empty, the library reads DJANGO_SECRET_KEY.
    Salt      string // The signing salt. If empty, the library uses the Django default.
}
```

`DecodeSession` returns `sessions.ErrInvalidSignature` when the signature does not match the secret key.

## Authenticate a Django login

`DecodeSession` verifies the session-data signature. It cannot check database expiry,
logout/deletion, the current user, or password changes. Use `Authenticator` for
protected routes. It performs three checks:

1. Load the current session row and require `expire_date` to be in the future.
2. Require authentication fields, an enabled supported backend, and a current active user.
3. Compare `_auth_user_hash` with Django's hash of the current encoded password field
   and `SECRET_KEY`, in constant time. Password changes invalidate older sessions.

Configure `AuthenticationBackends` to match Django's `AUTHENTICATION_BACKENDS` and
`CookieName` to match `SESSION_COOKIE_NAME` (default `sessionid`). The secret is required;
there is no demo-secret fallback. Database callbacks must use parameterized queries,
read current records, return `nil, nil` for missing rows, and propagate storage errors.
Avoid stale caches: they can delay logout, password-change, and account-disable checks.

For example, with `database/sql` and PostgreSQL placeholders:

```go
func loadSession(ctx context.Context, key string) (*sessions.SessionRecord, error) {
    var row sessions.SessionRecord
    err := db.QueryRowContext(ctx, `
        SELECT session_data, expire_date FROM django_session
        WHERE session_key = $1 AND expire_date > CURRENT_TIMESTAMP`, key).
        Scan(&row.Data, &row.ExpiresAt)
    if errors.Is(err, sql.ErrNoRows) {
        return nil, nil
    }
    if err != nil {
        return nil, err
    }
    return &row, nil
}

func loadUser(ctx context.Context, id string) (*sessions.AuthUser, error) {
    var user sessions.AuthUser
    err := db.QueryRowContext(ctx, `
        SELECT id, password, is_active FROM auth_user WHERE id = $1`, id).
        Scan(&user.ID, &user.Password, &user.IsActive)
    if errors.Is(err, sql.ErrNoRows) {
        return nil, nil
    }
    if err != nil {
        return nil, err
    }
    return &user, nil
}

// db is your configured *sql.DB. Import context, database/sql, errors, and
// sessions "github.com/soccer99/go-django-sessions".
auth := sessions.Authenticator{
    Options: sessions.SessionOptions{SecretKey: os.Getenv("DJANGO_SECRET_KEY")},
    LoadSession: loadSession,
    LoadUser: loadUser,
    AuthenticationBackends: []string{sessions.ModelBackend},
}
```

`AuthUser.Password` must be the **complete encoded Django password field**, never a
plaintext password. Adapt the user query to your schema; IDs must use Django's serialized
string representation. Malformed IDs must produce no user rather than be coerced to another
ID. For an integer primary key, validate/parse the ID before the SQL query if your database
would otherwise reject it as a storage error.

### Standard library, Chi, Gorilla Mux, and httprouter

```go
mux := http.NewServeMux()
mux.HandleFunc("GET /api/profile", func(w http.ResponseWriter, r *http.Request) {
    identity, _ := sessions.IdentityFromContext(r.Context())
    fmt.Fprintf(w, "user id: %s\n", identity.UserID)
})
http.ListenAndServe(":8080", auth.Middleware(mux))
```

Protect only routes that require a login. With Chi, use `protected.Use(auth.Middleware)`
on a subrouter. With Gorilla Mux, use `protected.Use(auth.Middleware)` on a subrouter.
With httprouter, wrap a protected `router.Handler` registration or wrap a router containing
only protected routes. The same middleware works with any `net/http`-compatible framework.

### Gin

```go
api := router.Group("/api", func(c *gin.Context) {
    called := false
    auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        called = true
        c.Request = r
        c.Next()
    })).ServeHTTP(c.Writer, c.Request)
    if !called {
        c.Abort()
    }
})
api.GET("/profile", func(c *gin.Context) {
    identity, _ := sessions.IdentityFromContext(c.Request.Context())
    c.JSON(http.StatusOK, identity)
})
```

### Echo v4

```go
api := router.Group("/api", echo.WrapMiddleware(auth.Middleware))
api.GET("/profile", func(c echo.Context) error {
    identity, _ := sessions.IdentityFromContext(c.Request().Context())
    return c.JSON(http.StatusOK, identity)
})
```

### Fiber v2 and v3

Fiber uses its own request types. Call the same authenticator from its middleware:

```go
cookieName := auth.CookieName
if cookieName == "" {
    cookieName = "sessionid"
}
api := app.Group("/api", func(c *fiber.Ctx) error { // v3: c fiber.Ctx
    identity, err := auth.Authenticate(c.UserContext(), c.Cookies(cookieName)) // v3: c.Context()
    if err != nil {
        if errors.Is(err, sessions.ErrUnauthenticated) {
            return c.Status(http.StatusUnauthorized).SendString("unauthenticated")
        }
        return c.Status(http.StatusInternalServerError).SendString("authentication unavailable")
    }
    c.Locals("djangoIdentity", identity)
    return c.Next()
})
api.Get("/profile", func(c *fiber.Ctx) error { // v3: c fiber.Ctx
    return c.JSON(c.Locals("djangoIdentity").(*sessions.Identity))
})
```

The `net/http` middleware sends 401 for an invalid login and 500 for configuration/storage
errors, and never invokes the protected handler on failure. Framework adapters follow the
same behavior. No password or decoded session map is attached to the handler identity.

### Additional authentication backends

`Authenticator` supports `sessions.ModelBackend` and `sessions.AllauthBackend`
(`allauth.account.auth_backends.AuthenticationBackend`) through `LoadUser`.
For PostPrint, include `sessions.AllauthBackend` in `AuthenticationBackends`, matching
Django's configuration. No extra loader is needed for allauth's inherited user lookup.

Register other backend paths explicitly:

```go
auth.BackendUserLoaders = map[string]func(context.Context, string) (*sessions.AuthUser, error){
    "myproject.auth.CustomModelBackend": loadUser,
    "myproject.auth.RestrictedBackend": loadRestrictedUser,
}
```

Reuse `loadUser` only when the backend has the same user lookup and eligibility
rules as ModelBackend. Otherwise the callback must mirror its Python `get_user`
behavior, returning `nil, nil` for rejected users. Registration does not enable a
backend: it must also appear in `AuthenticationBackends`. Unregistered backend
paths are rejected. The active-user and default session-auth-hash checks always
apply, including to custom loaders. Custom auth hashes or backends intentionally
allowing inactive users need a separate integration. This registers session user
lookup, not credential authentication or permission checks.

`LoginManager` still writes ModelBackend sessions and requires ModelBackend to be
configured; these additional backends apply to reading existing Django logins.

### Supported boundaries

- Database-backed sessions (`django.contrib.sessions.backends.db`), default JSON serialization,
  standard 32-character lowercase alphanumeric session keys, and string user IDs.
- ModelBackend, allauth, and explicitly registered backend user loaders with the default
  `AbstractBaseUser.get_session_auth_hash()` implementation. Custom auth hashes
  and other session stores require a separate integration, such as validation by Django.
- Current `SECRET_KEY` only. Old-key signatures/hashes are rejected. This deliberately logs out
  old sessions after rotation; it does not implement `SECRET_KEY_FALLBACKS`, Django's fallback
  session-key cycling. The Go authenticator is read-only; LoginManager writes new logins.
- Session expiry uses the database record, not the signing timestamp. Keep service/database clocks
  synchronized. Cookie lifetime alone does not establish server-side expiry.
- Authentication checks current state on each request; concurrent logout or user changes can race
  with an already authenticated request, as with normal request-time authentication.
- Permission checks and CSRF validation are outside this API. LoginManager rotates CSRF secrets.

### Runnable examples

Examples contain database callback stubs that return no records and therefore deny every
login until replaced. Use the database callbacks above or your equivalent implementation.
Set `DJANGO_SECRET_KEY` to Django's actual secret.

- Stdlib: `go run ./examples`
- Chi: `go get github.com/go-chi/chi/v5 && go run examples/chi.go`
- Gorilla Mux: `go get github.com/gorilla/mux && go run examples/gorilla.go`
- httprouter: `go get github.com/julienschmidt/httprouter && go run examples/httprouter.go`
- Gin: `go get github.com/gin-gonic/gin && go run examples/gin.go`
- Echo: `go get github.com/labstack/echo/v4 && go run examples/echo.go`
- Fiber v2: `go get github.com/gofiber/fiber/v2 && go run examples/fiber.go`
- Fiber v3: `go get github.com/gofiber/fiber/v3 && go run examples/fiber_v3.go`

Framework dependencies are optional and are not required by the library itself.

## Tests

```bash
go test -race ./...
go vet ./...
python3 testdata/test_frameworks.py
```

PostgreSQL integration tests live in a separate module so the library keeps zero
third-party dependencies. They use a temporary table and run in CI against
PostgreSQL 16. To run locally:

```bash
cd testdata/postgres
DJANGO_TEST_POSTGRES_DSN='host=localhost user=postgres password=postgres dbname=postgres sslmode=disable' go test -v ./...
```

The Django tests also verify that Django recognizes a Go-created database login
and rejects it after a password change.

The Django tests need [uv](https://docs.astral.sh/uv/). They encode data in a real Django install and decode it in Go, and the reverse. They also compare authentication hashes and authenticate real Django-encoded login sessions. They run against Django 4.2, 5.2, and the latest release on PyPI. If `uv` is not installed, the tests skip the Django checks.

The framework checks test the actual example adapters against valid and invalid requests in isolated temporary modules, using pinned framework versions. They require network access for dependencies and may download a newer Go toolchain required by Fiber v3.

## License

MIT

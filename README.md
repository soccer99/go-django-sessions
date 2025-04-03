# go-django-sessions

A lightweight Go library that allows you to decode and use Django session data in your Go applications. Perfect for scenarios where you need to share authentication between Django and Go services.

[![Go Reference](https://pkg.go.dev/badge/github.com/soccer99/go-django-sessions.svg)](https://pkg.go.dev/github.com/soccer99/go-django-sessions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- Decode Django session data in Go applications
- Handles both compressed and uncompressed session data
- Easy integration with standard Go web frameworks
- Supports custom secret keys and salt configurations
- Zero external dependencies beyond Go standard library

## Installation

```bash
go get github.com/soccer99/go-django-sessions
```

## Usage

### Basic Usage

```go
package main

import (
    "fmt"
    "log"

    "github.com/soccer99/go-django-sessions/session"
)

func main() {
    // Session data from django_sessions table
    sessionData := "your_session_data_here"

    sessionInfo, err := session.DecodeSession(sessionData, session.SessionOptions{
        SecretKey: "your_django_secret_key",
    })
    if err != nil {
        log.Fatalf("Failed to decode session: %v", err)
    }

    // Access the session data as a map
    sessionMap, ok := sessionInfo.(map[string]interface{})
    if !ok {
        log.Fatalf("Session data is not a map as expected")
    }

    // Extract the auth user ID
    if authUserID, exists := sessionMap["_auth_user_id"]; exists {
        fmt.Printf("Authenticated user ID: %v\n", authUserID)
    }

    // Print all session data
    fmt.Printf("%+v\n", sessionMap)
    // Output:
    // map[_auth_user_backend:django.contrib.auth.backends.ModelBackend _auth_user_hash:test _auth_user_id:1 test:test]
}
```

### HTTP Middleware Example (with standard library)

```go
package main

import (
    "context"
    "fmt"
    "net/http"

    "github.com/soccer99/go-django-sessions/session"
)

func djangoSessionMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Get the session cookie
        cookie, err := r.Cookie("sessionid")
        if err != nil {
            http.Error(w, "No session provided", http.StatusUnauthorized)
            return
        }

        // TODO: Add your own session data retrieval logic here
        sessionData := getSessionData(cookie.Value)

        if sessionData == "" {
            http.Error(w, "No session data found", http.StatusUnauthorized)
            return
        }

        // Decode the session
        sessionInfo, err := session.DecodeSession(sessionData, session.SessionOptions{
            SecretKey: "your_django_secret_key",
        })
        if err != nil {
            http.Error(w, "Invalid session", http.StatusUnauthorized)
            return
        }

        // Add the session to request context
        ctx := context.WithValue(r.Context(), "djangoSession", sessionInfo)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

func getSessionData(sessionID string) string {
    // Implement your database lookup logic here
    return "your_session_data_here"
}

func main() {
    mux := http.NewServeMux()

    // Protected endpoint
    mux.HandleFunc("/api/protected", func(w http.ResponseWriter, r *http.Request) {
        session := r.Context().Value("djangoSession")
        fmt.Fprintf(w, "Hello, you're authenticated! Session: %v", session)
    })

    // Apply middleware
    handler := djangoSessionMiddleware(mux)

    http.ListenAndServe(":8080", handler)
}
```

## Configuration

The `DecodeSession` function accepts the following options:

```go
type SessionOptions struct {
    SecretKey string  // Django's SECRET_KEY (can also be set via DJANGO_SECRET_KEY env var)
    Salt      string  // Custom salt if your Django config uses one
}
```

### Environment Variables

- `DJANGO_SECRET_KEY`: Your Django project's secret key. This can be used instead of passing the key in options.

## Helper Functions

The library provides some additional helper functions to make working with Django sessions easier:

```go
// Extract the auth user ID directly
userID, err := session.GetAuthUserID(sessionInfo)
if err != nil {
    log.Fatalf("Failed to get auth user ID: %v", err)
}
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT

## Credits

Inspired by the need to bridge Django and Go applications in modern microservice architectures.

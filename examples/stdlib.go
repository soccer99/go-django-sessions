// Standard library example. Run: go run ./examples
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	sessions "github.com/soccer99/go-django-sessions"
)

// Replace these callbacks with current database reads; see README.md for SQL.
// Missing records return nil, nil. Storage failures return an error.
func loadSession(ctx context.Context, key string) (*sessions.SessionRecord, error) {
	return nil, nil
}
func loadUser(ctx context.Context, id string) (*sessions.AuthUser, error) {
	return nil, nil
}

func main() {
	auth := sessions.Authenticator{
		Options:                sessions.SessionOptions{}, // DJANGO_SECRET_KEY is required.
		LoadSession:            loadSession,
		LoadUser:               loadUser,
		AuthenticationBackends: []string{sessions.ModelBackend},
	}
	log.Fatal(http.ListenAndServe(":8080", buildRouter(auth)))
}

func buildRouter(auth sessions.Authenticator) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/profile", func(w http.ResponseWriter, r *http.Request) {
		identity, _ := sessions.IdentityFromContext(r.Context())
		fmt.Fprintf(w, "user id: %s\n", identity.UserID)
	})
	return auth.Middleware(mux)
}

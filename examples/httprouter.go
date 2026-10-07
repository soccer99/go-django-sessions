//go:build ignore

// Standalone example. See README.md for dependency installation.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/julienschmidt/httprouter"
	sessions "github.com/soccer99/go-django-sessions"
)

// Replace these with current database reads; see README.md for SQL.
func loadSession(ctx context.Context, key string) (*sessions.SessionRecord, error) { return nil, nil }
func loadUser(ctx context.Context, id string) (*sessions.AuthUser, error)          { return nil, nil }

func main() {
	auth := sessions.Authenticator{
		Options:                sessions.SessionOptions{},
		LoadSession:            loadSession,
		LoadUser:               loadUser,
		AuthenticationBackends: []string{sessions.ModelBackend},
	}
	log.Fatal(http.ListenAndServe(":8080", buildRouter(auth)))
}

func buildRouter(auth sessions.Authenticator) http.Handler {
	profile := func(w http.ResponseWriter, r *http.Request) {
		identity, _ := sessions.IdentityFromContext(r.Context())
		fmt.Fprintf(w, "user id: %s\n", identity.UserID)
	}
	router := httprouter.New()
	router.Handler("GET", "/api/profile", auth.Middleware(http.HandlerFunc(profile)))
	return router
}

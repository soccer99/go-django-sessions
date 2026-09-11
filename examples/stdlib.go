// Standard library example. Run:
//
//	go run ./examples
package main

import (
	"context"
	"fmt"
	"net/http"

	sessions "github.com/soccer99/go-django-sessions"
)

type ctxKey struct{}

// getSessionData reads the session_data column for a session key.
// Replace this with a query on the django_session table.
func getSessionData(sessionID string) string {
	return ""
}

// djangoSessionMiddleware checks the Django session cookie and puts the session in the context.
func djangoSessionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("sessionid")
		if err != nil {
			http.Error(w, "no session cookie", http.StatusUnauthorized)
			return
		}
		raw := getSessionData(cookie.Value)
		if raw == "" {
			http.Error(w, "session not found", http.StatusUnauthorized)
			return
		}
		session, err := sessions.DecodeSession(raw, sessions.SessionOptions{})
		if err != nil {
			http.Error(w, "invalid session", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, session)))
	})
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/profile", func(w http.ResponseWriter, r *http.Request) {
		session := r.Context().Value(ctxKey{}).(map[string]any)
		fmt.Fprintf(w, "user id: %v\n", session["_auth_user_id"])
	})
	http.ListenAndServe(":8080", djangoSessionMiddleware(mux))
}

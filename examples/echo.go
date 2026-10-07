//go:build ignore

// Standalone example. See README.md for dependency installation.
package main

import (
	"context"
	"log"
	"net/http"

	"github.com/labstack/echo/v4"
	sessions "github.com/soccer99/go-django-sessions"
)

// Replace these with current database reads; see README.md for SQL.
func loadSession(ctx context.Context, key string) (*sessions.SessionRecord, error) {
	return nil, nil
}
func loadUser(ctx context.Context, id string) (*sessions.AuthUser, error) {
	return nil, nil
}

func main() {
	auth := sessions.Authenticator{
		Options:                sessions.SessionOptions{},
		LoadSession:            loadSession,
		LoadUser:               loadUser,
		AuthenticationBackends: []string{sessions.ModelBackend},
	}
	log.Fatal(buildRouter(auth).Start(":8080"))
}

func buildRouter(auth sessions.Authenticator) *echo.Echo {
	router := echo.New()
	api := router.Group("/api", echo.WrapMiddleware(auth.Middleware))
	api.GET("/profile", func(c echo.Context) error {
		identity, _ := sessions.IdentityFromContext(c.Request().Context())
		return c.JSON(http.StatusOK, identity)
	})
	return router
}

//go:build ignore

// Standalone example. See README.md for dependency installation.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"

	"github.com/gofiber/fiber/v3"
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
	log.Fatal(buildRouter(auth).Listen(":8080"))
}

func buildRouter(auth sessions.Authenticator) *fiber.App {
	app := fiber.New()
	// Scope this middleware to protected routes only.
	api := app.Group("/api", func(c fiber.Ctx) error {
		identity, err := auth.Authenticate(c.Context(), c.Cookies("sessionid"))
		if err != nil {
			if errors.Is(err, sessions.ErrUnauthenticated) {
				return c.Status(http.StatusUnauthorized).SendString("unauthenticated")
			}
			return c.Status(http.StatusInternalServerError).SendString("authentication unavailable")
		}
		c.Locals("djangoIdentity", identity)
		return c.Next()
	})
	api.Get("/profile", func(c fiber.Ctx) error {
		identity := c.Locals("djangoIdentity").(*sessions.Identity)
		return c.JSON(identity)
	})
	return app
}

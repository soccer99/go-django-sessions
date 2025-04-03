package main

import (
	"fmt"
	"log"
	"os"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	sessions "github.com/soccer99/go-django-sessions"
)

// User is a simplified user representation
type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

// getSessionData would typically fetch from a database
// This is a simplified example for demonstration
func getSessionData(sessionID string) string {
	// In a real app, you would query the django_sessions table
	// Example SQL: SELECT session_data FROM django_sessions WHERE session_key = $1

	// For this example, we return a mock session string
	// Replace this with actual database logic
	mockSessions := map[string]string{
		"test-session-id": "your-django-session-data-here",
	}

	return mockSessions[sessionID]
}

// fetchUserDetails would normally query a database for user info
func fetchUserDetails(userID string) (*User, error) {
	// Simulate database lookup
	// In a real app, you would query your user table
	if userID == "1" {
		return &User{
			ID:       "1",
			Username: "django_user",
			Email:    "user@example.com",
		}, nil
	}
	return nil, fmt.Errorf("user not found")
}

// djangoSessionMiddleware validates Django session cookies
func djangoSessionMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get Django session cookie
		sessionID := c.Cookies("sessionid")
		if sessionID == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "No session cookie found",
			})
		}

		// Get the raw session data
		sessionData := getSessionData(sessionID)
		if sessionData == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Session not found",
			})
		}

		// Get Django secret key from environment or use a hardcoded one for example
		secretKey := os.Getenv("DJANGO_SECRET_KEY")
		if secretKey == "" {
			// For demonstration only - in production, always use environment variables
			secretKey = "your-django-secret-key-here"
		}

		// Decode the session
		sessionData, err := sessions.DecodeSession(sessionData, sessions.SessionOptions{
			SecretKey: secretKey,
		})
		if err != nil {
			log.Printf("Session decode error: %v", err)
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid session",
			})
		}

		// Check if user is authenticated
		authUserID, exists := sessionData["_auth_user_id"]
		if !exists {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Not authenticated",
			})
		}

		// Convert auth user ID to string based on its type
		var userIDStr string
		switch v := authUserID.(type) {
		case string:
			userIDStr = v
		case float64:
			userIDStr = fmt.Sprintf("%.0f", v)
		default:
			userIDStr = fmt.Sprintf("%v", v)
		}

		// Get user details from database
		user, err := fetchUserDetails(userIDStr)
		if err != nil {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "User not found",
			})
		}

		// Add user to context for route handlers
		c.Locals("user", user)
		c.Locals("djangoSession", sessionMap)

		return c.Next()
	}
}

func main() {
	app := fiber.New()

	// Add logging middleware
	app.Use(logger.New())

	// Public routes
	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Welcome to the Go-Django Integration Example")
	})

	// Protected API routes
	api := app.Group("/api", djangoSessionMiddleware())

	// Get the current user's profile
	api.Get("/profile", func(c *fiber.Ctx) error {
		user := c.Locals("user").(*User)
		return c.JSON(fiber.Map{
			"user":    user,
			"session": c.Locals("djangoSession"),
		})
	})

	// Start the server
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}

	log.Printf("Starting server on port %s", port)
	log.Fatal(app.Listen(":" + port))
}

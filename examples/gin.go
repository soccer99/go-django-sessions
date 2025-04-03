package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/soccer99/go-django-sessions/session"
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

// DjangoSessionMiddleware validates Django session cookies
func DjangoSessionMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get Django session cookie
		sessionID, err := c.Cookie("sessionid")
		if err != nil || sessionID == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "No session cookie found",
			})
			return
		}

		// Get the raw session data
		sessionData := getSessionData(sessionID)
		if sessionData == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Session not found",
			})
			return
		}

		// Get Django secret key from environment or use a hardcoded one for example
		secretKey := os.Getenv("DJANGO_SECRET_KEY")
		if secretKey == "" {
			// For demonstration only - in production, always use environment variables
			secretKey = "your-django-secret-key-here"
		}

		// Decode the session
		sessionInfo, err := session.DecodeSession(sessionData, session.SessionOptions{
			SecretKey: secretKey,
		})
		if err != nil {
			log.Printf("Session decode error: %v", err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid session",
			})
			return
		}

		// Extract session info
		sessionMap, ok := sessionInfo.(map[string]interface{})
		if !ok {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": "Invalid session format",
			})
			return
		}

		// Check if user is authenticated
		authUserID, exists := sessionMap["_auth_user_id"]
		if !exists {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Not authenticated",
			})
			return
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
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
				"error": "User not found",
			})
			return
		}

		// Add user to context for route handlers
		c.Set("user", user)
		c.Set("djangoSession", sessionMap)

		c.Next()
	}
}

func main() {
	// Set Gin to release mode in production
	if os.Getenv("GIN_MODE") == "" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.Default()

	// Public routes
	router.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "Welcome to the Go-Django Integration Example")
	})

	// Protected API routes
	api := router.Group("/api")
	api.Use(DjangoSessionMiddleware())

	// Get the current user's profile
	api.GET("/profile", func(c *gin.Context) {
		user, _ := c.Get("user")
		session, _ := c.Get("djangoSession")

		c.JSON(http.StatusOK, gin.H{
			"user":    user,
			"session": session,
		})
	})

	// Start the server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Starting server on port %s", port)
	log.Fatal(router.Run(":" + port))
}

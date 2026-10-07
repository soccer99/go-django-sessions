package go_django_sessions

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// ModelBackend is the supported Django authentication backend.
const ModelBackend = "django.contrib.auth.backends.ModelBackend"

// ErrUnauthenticated means the session does not represent a current login.
var ErrUnauthenticated = errors.New("unauthenticated")

// SessionRecord must come from the current django_session row, not a client
// supplied session_data value. A missing row is represented by nil, nil.
type SessionRecord struct {
	Data      string
	ExpiresAt time.Time
}

// AuthUser describes the current Django user. Password is the complete encoded
// password field from the database, not the plaintext password. This API supports
// AbstractBaseUser's default get_session_auth_hash and ModelBackend only.
type AuthUser struct {
	ID       string
	Password string
	IsActive bool
}

// Identity contains only the verified user ID. Passwords and session data are
// deliberately excluded from the identity passed to handlers.
type Identity struct {
	UserID string `json:"user_id"`
}

// Authenticator verifies database-backed Django logins. Callbacks must read
// current records and return nil, nil for missing records; other errors are
// propagated so callers can distinguish unavailable storage from a bad login.
// Configure this value once before serving requests and do not mutate it.
type Authenticator struct {
	Options     SessionOptions
	LoadSession func(context.Context, string) (*SessionRecord, error)
	LoadUser    func(context.Context, string) (*AuthUser, error)
	// AuthenticationBackends must match Django's AUTHENTICATION_BACKENDS.
	// Only ModelBackend is supported, even if other entries are configured.
	AuthenticationBackends []string
	// CookieName defaults to sessionid. Match Django's SESSION_COOKIE_NAME.
	CookieName string
}

// SessionAuthHash implements AbstractBaseUser.get_session_auth_hash. It uses a
// different salt and representation from the session-data signature.
func SessionAuthHash(encodedPassword, secretKey string) string {
	const salt = "django.contrib.auth.models.AbstractBaseUser.get_session_auth_hash"
	key := sha256.Sum256([]byte(salt + secretKey))
	h := hmac.New(sha256.New, key[:])
	h.Write([]byte(encodedPassword))
	return hex.EncodeToString(h.Sum(nil))
}

// Authenticate checks expiry, the configured backend/current user, and the
// authentication hash. It does not check permissions or CSRF. Invalid logins
// return ErrUnauthenticated; configuration and lookup errors return other errors.
// Old-secret sessions are rejected: SECRET_KEY_FALLBACKS migration is unsupported.
func (a Authenticator) Authenticate(ctx context.Context, sessionKey string) (*Identity, error) {
	key, _, err := a.Options.resolve()
	if err != nil {
		return nil, err
	}
	if a.LoadSession == nil || a.LoadUser == nil || len(a.AuthenticationBackends) == 0 {
		return nil, errors.New("authenticator requires session/user loaders and authentication backends")
	}
	// Django generates 32-character lowercase alphanumeric database session keys.
	if len(sessionKey) != 32 {
		return nil, ErrUnauthenticated
	}
	for _, c := range sessionKey {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return nil, ErrUnauthenticated
		}
	}
	record, err := a.LoadSession(ctx, sessionKey)
	if err != nil {
		return nil, fmt.Errorf("load session: %w", err)
	}
	if record == nil || !record.ExpiresAt.After(time.Now()) {
		return nil, ErrUnauthenticated
	}
	data, err := DecodeSession(record.Data, a.Options)
	if err != nil {
		return nil, ErrUnauthenticated
	}
	userID, idOK := data["_auth_user_id"].(string)
	backend, backendOK := data["_auth_user_backend"].(string)
	sessionHash, hashOK := data["_auth_user_hash"].(string)
	if !idOK || userID == "" || !backendOK || backend != ModelBackend || !hashOK || sessionHash == "" {
		return nil, ErrUnauthenticated
	}
	enabled := false
	for _, configured := range a.AuthenticationBackends {
		if configured == backend {
			enabled = true
			break
		}
	}
	if !enabled {
		return nil, ErrUnauthenticated
	}
	user, err := a.LoadUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("load user: %w", err)
	}
	if user == nil || !user.IsActive || user.ID != userID || user.Password == "" {
		return nil, ErrUnauthenticated
	}
	if !hmac.Equal([]byte(sessionHash), []byte(SessionAuthHash(user.Password, key))) {
		return nil, ErrUnauthenticated
	}
	return &Identity{UserID: userID}, nil
}

type identityContextKey struct{}

// IdentityFromContext retrieves the identity installed by Middleware.
func IdentityFromContext(ctx context.Context) (*Identity, bool) {
	identity, ok := ctx.Value(identityContextKey{}).(*Identity)
	return identity, ok && identity != nil
}

// Middleware protects net/http handlers, including Chi, Gorilla Mux, and
// httprouter handlers. It returns 401 for invalid logins and 500 for configuration
// or storage errors without exposing internal errors to the client.
func (a Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := a.CookieName
		if name == "" {
			name = "sessionid"
		}
		cookie, err := r.Cookie(name)
		if err != nil {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		identity, err := a.Authenticate(r.Context(), cookie.Value)
		if err != nil {
			status := http.StatusInternalServerError
			message := "authentication unavailable"
			if errors.Is(err, ErrUnauthenticated) {
				status, message = http.StatusUnauthorized, "unauthenticated"
			}
			http.Error(w, message, status)
			return
		}
		ctx := context.WithValue(r.Context(), identityContextKey{}, identity)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

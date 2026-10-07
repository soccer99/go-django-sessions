package go_django_sessions

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testSessionKey = "abcdefghijklmnopqrstuvwxyz012345"

func authFixture(t *testing.T) (Authenticator, *SessionRecord, *AuthUser, map[string]any) {
	t.Helper()
	user := &AuthUser{ID: "1", Password: "pbkdf2_sha256$600000$salt$encoded", IsActive: true}
	data := map[string]any{"_auth_user_id": user.ID, "_auth_user_backend": ModelBackend,
		"_auth_user_hash": SessionAuthHash(user.Password, opts.SecretKey)}
	raw, err := EncodeSession(data, opts)
	if err != nil {
		t.Fatal(err)
	}
	record := &SessionRecord{Data: raw, ExpiresAt: time.Now().Add(time.Hour)}
	auth := Authenticator{Options: opts, AuthenticationBackends: []string{ModelBackend},
		LoadSession: func(context.Context, string) (*SessionRecord, error) { return record, nil },
		LoadUser:    func(context.Context, string) (*AuthUser, error) { return user, nil }}
	return auth, record, user, data
}

func TestAuthenticationBoundaries(t *testing.T) {
	for _, name := range []string{"valid", "expired", "zero expiry", "missing session", "tampered", "anonymous", "numeric id", "empty id", "missing backend", "custom backend", "removed backend", "missing hash", "bad hash", "password changed", "inactive", "deleted user", "wrong user", "empty password", "old secret"} {
		t.Run(name, func(t *testing.T) {
			a, record, user, data := authFixture(t)
			switch name {
			case "expired":
				record.ExpiresAt = time.Now().Add(-time.Second)
			case "zero expiry":
				record.ExpiresAt = time.Time{}
			case "missing session":
				a.LoadSession = func(context.Context, string) (*SessionRecord, error) { return nil, nil }
			case "anonymous":
				delete(data, "_auth_user_id")
			case "numeric id":
				data["_auth_user_id"] = 1
			case "empty id":
				data["_auth_user_id"] = ""
			case "missing backend":
				delete(data, "_auth_user_backend")
			case "custom backend":
				data["_auth_user_backend"] = "custom.Backend"
			case "removed backend":
				a.AuthenticationBackends = []string{"custom.Backend"}
			case "missing hash":
				delete(data, "_auth_user_hash")
			case "bad hash":
				data["_auth_user_hash"] = "wrong"
			case "password changed":
				user.Password += "changed"
			case "inactive":
				user.IsActive = false
			case "deleted user":
				a.LoadUser = func(context.Context, string) (*AuthUser, error) { return nil, nil }
			case "wrong user":
				user.ID = "2"
			case "empty password":
				user.Password = ""
			case "old secret":
				a.Options.SecretKey = "new-secret"
			}
			var err error
			record.Data, err = EncodeSession(data, opts)
			if err != nil {
				t.Fatal(err)
			}
			if name == "tampered" {
				record.Data += "x"
			}
			identity, err := a.Authenticate(context.Background(), testSessionKey)
			if name == "valid" {
				if err != nil || identity == nil || identity.UserID != "1" {
					t.Fatalf("%v %v", identity, err)
				}
			} else if identity != nil || !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("accepted invalid login: %v %v", identity, err)
			}
		})
	}
}

func TestAuthenticationErrors(t *testing.T) {
	a, _, _, _ := authFixture(t)
	for _, key := range []string{"", "short", strings.Repeat("A", 32), strings.Repeat("!", 32)} {
		if _, err := a.Authenticate(context.Background(), key); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("key %q: %v", key, err)
		}
	}
	storageErr := errors.New("database unavailable")
	a.LoadSession = func(context.Context, string) (*SessionRecord, error) { return nil, storageErr }
	if _, err := a.Authenticate(context.Background(), testSessionKey); !errors.Is(err, storageErr) {
		t.Fatal(err)
	}
	a, _, _, _ = authFixture(t)
	a.LoadUser = func(context.Context, string) (*AuthUser, error) { return nil, storageErr }
	if _, err := a.Authenticate(context.Background(), testSessionKey); !errors.Is(err, storageErr) {
		t.Fatal(err)
	}
	a.LoadUser = nil
	if _, err := a.Authenticate(context.Background(), testSessionKey); err == nil || errors.Is(err, ErrUnauthenticated) {
		t.Fatal(err)
	}
}

func TestMiddleware(t *testing.T) {
	for _, name := range []string{"valid", "missing cookie", "invalid", "expired", "storage error", "configuration error", "custom cookie"} {
		t.Run(name, func(t *testing.T) {
			a, record, _, _ := authFixture(t)
			cookieName := "sessionid"
			want := http.StatusOK
			switch name {
			case "missing cookie", "invalid":
				want = http.StatusUnauthorized
			case "expired":
				record.ExpiresAt = time.Now().Add(-time.Second)
				want = http.StatusUnauthorized
			case "storage error":
				a.LoadSession = func(context.Context, string) (*SessionRecord, error) {
					return nil, errors.New("private storage detail")
				}
				want = http.StatusInternalServerError
			case "configuration error":
				a.LoadUser = nil
				want = http.StatusInternalServerError
			case "custom cookie":
				cookieName = "custom_session"
				a.CookieName = cookieName
			}
			called := false
			h := a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				identity, ok := IdentityFromContext(r.Context())
				if !ok || identity.UserID != "1" {
					t.Fatal("missing identity")
				}
				w.WriteHeader(http.StatusOK)
			}))
			r := httptest.NewRequest("GET", "/", nil)
			if name != "missing cookie" {
				value := testSessionKey
				if name == "invalid" {
					value = "invalid"
				}
				r.AddCookie(&http.Cookie{Name: cookieName, Value: value})
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != want || called != (want == http.StatusOK) || strings.Contains(w.Body.String(), "private") {
				t.Fatalf("status=%d called=%v body=%s", w.Code, called, w.Body.String())
			}
		})
	}
}

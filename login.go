package go_django_sessions

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"
)

var (
	ErrSessionCollision   = errors.New("session key collision")
	ErrSessionInterrupted = errors.New("session changed or deleted during login")
)

// LoginStore persists database sessions. Commit must atomically compare the
// current old row with expected, save the new row, and delete oldKey on rotation.
// A nil expected means create only. Return ErrSessionCollision on key conflicts
// and ErrSessionInterrupted if expected no longer matches. Never upsert updates.
type LoginStore interface {
	Load(context.Context, string) (*SessionRecord, error)
	Commit(ctx context.Context, oldKey, newKey string, expected, record *SessionRecord) error
	Delete(context.Context, string) error
}

// CookieSettings maps to Django's SESSION_COOKIE_* or CSRF_COOKIE_* settings.
// Use DefaultSessionCookie/DefaultCSRFCookie and adjust to match your project.
type CookieSettings struct {
	Name, Path, Domain string
	Secure, HTTPOnly   bool
	SameSite           http.SameSite
}

func DefaultSessionCookie() CookieSettings {
	return CookieSettings{Name: "sessionid", Path: "/", HTTPOnly: true, SameSite: http.SameSiteLaxMode}
}
func DefaultCSRFCookie() CookieSettings {
	return CookieSettings{Name: "csrftoken", Path: "/", SameSite: http.SameSiteLaxMode}
}

// LoginManager writes logins for ModelBackend and the default AbstractBaseUser
// auth hash. Credentials must already have been verified by the caller. Custom
// authentication backends/user hash overrides require a separate integration.
// Configure once before serving requests.
type LoginManager struct {
	Options                SessionOptions
	Store                  LoginStore
	AuthenticationBackends []string
	SessionCookie          *CookieSettings
	CSRFCookie             *CookieSettings
	SessionAge             time.Duration // Zero uses Django's default of 14 days.
	ExpireAtBrowserClose   bool
	CSRFUseSessions        bool
	CSRFAge                time.Duration // Zero uses Django CSRF_COOKIE_AGE: 31449600 seconds.
	// AfterLogin implements application effects such as last_login/audit hooks.
	// It runs after persistence, before cookies. An error leaves the session saved;
	// return an error response and do not retry non-idempotent hooks blindly.
	AfterLogin func(context.Context, *AuthUser) error
}

func randomString(alphabet string) (string, error) {
	b := make([]byte, 32)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", err
		}
		b[i] = alphabet[n.Int64()]
	}
	return string(b), nil
}
func validSessionKey(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
func (m LoginManager) cookies() (CookieSettings, CookieSettings, error) {
	s, c := DefaultSessionCookie(), DefaultCSRFCookie()
	if m.SessionCookie != nil {
		s = *m.SessionCookie
	}
	if m.CSRFCookie != nil {
		c = *m.CSRFCookie
	}
	for _, v := range []CookieSettings{s, c} {
		if err := (&http.Cookie{Name: v.Name, Value: "x", Path: v.Path, Domain: v.Domain, Secure: v.Secure, HttpOnly: v.HTTPOnly, SameSite: v.SameSite}).Valid(); err != nil {
			return s, c, err
		}
	}
	if !m.CSRFUseSessions && s.Name == c.Name {
		return s, c, errors.New("session and CSRF cookie names must differ")
	}
	return s, c, nil
}
func addVaryCookie(w http.ResponseWriter) {
	for _, v := range w.Header().Values("Vary") {
		for _, p := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(p), "Cookie") || strings.TrimSpace(p) == "*" {
				return
			}
		}
	}
	w.Header().Add("Vary", "Cookie")
}
func setCookie(w http.ResponseWriter, c CookieSettings, value string, expiry time.Time, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: c.Name, Value: value, Path: c.Path, Domain: c.Domain, Secure: c.Secure, HttpOnly: c.HTTPOnly, SameSite: c.SameSite, Expires: expiry, MaxAge: maxAge})
}
func (m LoginManager) expiry(data map[string]any, now time.Time) (time.Time, bool, error) {
	age := m.SessionAge
	if age == 0 {
		age = 14 * 24 * time.Hour
	}
	if age < time.Second {
		return time.Time{}, false, errors.New("session age must be at least one second")
	}
	browser := m.ExpireAtBrowserClose
	if value, ok := data["_session_expiry"]; ok && value != nil {
		switch v := value.(type) {
		case float64:
			browser = v == 0
			if v != 0 {
				if v != float64(int64(v)) || v <= 0 || v >= float64((1<<63-1)/int64(time.Second)) {
					return time.Time{}, false, errors.New("invalid session expiry")
				}
				age = time.Duration(v) * time.Second
			}
		case string:
			end, err := time.Parse(time.RFC3339Nano, v)
			if err != nil {
				return time.Time{}, false, fmt.Errorf("session expiry: %w", err)
			}
			return end, false, nil
		default:
			return time.Time{}, false, errors.New("unsupported session expiry")
		}
	}
	return now.Add(age), browser, nil
}

// Login saves the authenticated session before emitting cookies. It preserves
// anonymous data while rotating its key, flushes data on user/hash changes, and
// retains the key for an unchanged authenticated user, matching Django login.
// Do not call after writing response headers or for an unsuccessful response.
// CSRF rotation does not perform CSRF validation; protect unsafe routes separately.
func (m LoginManager) Login(w http.ResponseWriter, r *http.Request, user *AuthUser) (string, error) {
	secret, _, err := m.Options.resolve()
	if err != nil {
		return "", err
	}
	if m.Store == nil {
		return "", errors.New("login requires a session store")
	}
	enabled := false
	for _, b := range m.AuthenticationBackends {
		if b == ModelBackend {
			enabled = true
		}
	}
	if !enabled {
		return "", errors.New("ModelBackend must be configured")
	}
	if user == nil || user.ID == "" || !user.IsActive || user.Password == "" {
		return "", ErrUnauthenticated
	}
	sc, cc, err := m.cookies()
	if err != nil {
		return "", err
	}
	csrfAge := m.CSRFAge
	if csrfAge == 0 {
		csrfAge = 31449600 * time.Second
	}
	if !m.CSRFUseSessions && csrfAge < time.Second {
		return "", errors.New("CSRF cookie age must be at least one second")
	}
	oldKey := ""
	var old *SessionRecord
	data := map[string]any{}
	if cookie, e := r.Cookie(sc.Name); e == nil && validSessionKey(cookie.Value) {
		old, err = m.Store.Load(r.Context(), cookie.Value)
		if err != nil {
			return "", err
		}
		if old != nil && old.ExpiresAt.After(time.Now()) {
			oldKey = cookie.Value
			decoded, e := DecodeSession(old.Data, m.Options)
			if e == nil && decoded != nil {
				data = decoded
			}
		} else {
			old = nil
		}
	}
	hash := SessionAuthHash(user.Password, secret)
	rotate := true
	if id, ok := data["_auth_user_id"]; ok {
		previous, _ := data["_auth_user_hash"].(string)
		if id == user.ID && hmac.Equal([]byte(previous), []byte(hash)) {
			rotate = false
		} else {
			data = map[string]any{}
		}
	}
	data["_auth_user_id"] = user.ID
	data["_auth_user_backend"] = ModelBackend
	data["_auth_user_hash"] = hash
	csrf, err := randomString("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	if err != nil {
		return "", err
	}
	if m.CSRFUseSessions {
		data["_csrftoken"] = csrf
	}
	now := time.Now()
	expires, browser, err := m.expiry(data, now)
	if err != nil {
		return "", err
	}
	if !expires.After(now) {
		return "", errors.New("session expiry is in the past")
	}
	raw, err := EncodeSession(data, m.Options)
	if err != nil {
		return "", err
	}
	next := oldKey
	for attempt := 0; attempt < 32; attempt++ {
		if rotate || next == "" {
			next, err = randomString("abcdefghijklmnopqrstuvwxyz0123456789")
			if err != nil {
				return "", err
			}
			if next == oldKey {
				err = ErrSessionCollision
				continue
			}
		}
		err = m.Store.Commit(r.Context(), oldKey, next, old, &SessionRecord{Data: raw, ExpiresAt: expires})
		if errors.Is(err, ErrSessionCollision) && rotate {
			continue
		}
		break
	}
	if err != nil {
		return "", err
	}
	if m.AfterLogin != nil {
		if err = m.AfterLogin(r.Context(), user); err != nil {
			return "", err
		}
	}
	cookieExpiry := expires
	maxAge := int(expires.Sub(now) / time.Second)
	if browser {
		cookieExpiry = time.Time{}
		maxAge = 0
	}
	setCookie(w, sc, next, cookieExpiry, maxAge)
	if !m.CSRFUseSessions {
		setCookie(w, cc, csrf, now.Add(csrfAge), int(csrfAge/time.Second))
	}
	addVaryCookie(w)
	return next, nil
}

// Logout deletes the server session before clearing its cookie.
func (m LoginManager) Logout(w http.ResponseWriter, r *http.Request) error {
	if m.Store == nil {
		return errors.New("logout requires a session store")
	}
	sc, _, err := m.cookies()
	if err != nil {
		return err
	}
	if c, e := r.Cookie(sc.Name); e == nil && validSessionKey(c.Value) {
		if err = m.Store.Delete(r.Context(), c.Value); err != nil {
			return err
		}
	}
	setCookie(w, sc, "", time.Unix(0, 0), -1)
	addVaryCookie(w)
	return nil
}

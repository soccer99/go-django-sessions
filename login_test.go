package go_django_sessions

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type memoryLoginStore struct {
	rows        map[string]SessionRecord
	collision   bool
	interrupted bool
}

func (s *memoryLoginStore) Load(_ context.Context, key string) (*SessionRecord, error) {
	v, ok := s.rows[key]
	if !ok {
		return nil, nil
	}
	return &v, nil
}
func (s *memoryLoginStore) Commit(_ context.Context, old, next string, expected, record *SessionRecord) error {
	if s.interrupted {
		return ErrSessionInterrupted
	}
	if s.collision {
		s.collision = false
		return ErrSessionCollision
	}
	if expected != nil {
		v, ok := s.rows[old]
		if !ok || v != *expected {
			return ErrSessionInterrupted
		}
	}
	if old != next {
		if _, ok := s.rows[next]; ok {
			return ErrSessionCollision
		}
		delete(s.rows, old)
	}
	s.rows[next] = *record
	return nil
}
func (s *memoryLoginStore) Delete(_ context.Context, key string) error {
	delete(s.rows, key)
	return nil
}
func testLoginManager() (LoginManager, *memoryLoginStore, *AuthUser) {
	s := &memoryLoginStore{rows: map[string]SessionRecord{}}
	return LoginManager{Options: opts, Store: s, AuthenticationBackends: []string{ModelBackend}}, s, &AuthUser{ID: "1", Password: "pbkdf2_sha256$1000000$salt$encoded", IsActive: true}
}
func TestLoginLifecycle(t *testing.T) {
	for _, kind := range []string{"new", "anonymous", "same", "different", "changed-password", "corrupt", "expired"} {
		t.Run(kind, func(t *testing.T) {
			m, s, u := testLoginManager()
			old := "abcdefghijklmnopqrstuvwxyz012345"
			data := map[string]any{"cart": "keep"}
			if kind == "same" || kind == "different" || kind == "changed-password" {
				data["_auth_user_id"] = "1"
				data["_auth_user_hash"] = SessionAuthHash(u.Password, opts.SecretKey)
			}
			if kind == "different" {
				data["_auth_user_id"] = "2"
			}
			if kind == "changed-password" {
				data["_auth_user_hash"] = "stale"
			}
			raw, _ := EncodeSession(data, opts)
			if kind == "corrupt" {
				raw = "corrupt"
			}
			expires := time.Now().Add(time.Hour)
			if kind == "expired" {
				expires = time.Now().Add(-time.Hour)
			}
			r := httptest.NewRequest("POST", "https://example.test/login", nil)
			if kind != "new" {
				s.rows[old] = SessionRecord{Data: raw, ExpiresAt: expires}
				r.AddCookie(&http.Cookie{Name: "sessionid", Value: old})
			}
			w := httptest.NewRecorder()
			next, err := m.Login(w, r, u)
			if err != nil {
				t.Fatal(err)
			}
			if (next == old) != (kind == "same") {
				t.Fatalf("unexpected rotation: %s", next)
			}
			if kind != "same" && kind != "expired" {
				if _, ok := s.rows[old]; ok {
					t.Fatal("old key retained")
				}
			}
			got, err := DecodeSession(s.rows[next].Data, opts)
			if err != nil {
				t.Fatal(err)
			}
			preserve := kind == "anonymous" || kind == "same"
			if (got["cart"] == "keep") != preserve {
				t.Fatalf("wrong preserved data: %v", got)
			}
			a := Authenticator{Options: opts, AuthenticationBackends: []string{ModelBackend}, LoadSession: s.Load, LoadUser: func(context.Context, string) (*AuthUser, error) { return u, nil }}
			if _, err = a.Authenticate(context.Background(), next); err != nil {
				t.Fatal(err)
			}
			cookies := w.Result().Cookies()
			if len(cookies) != 2 || cookies[0].Value != next || !cookies[0].HttpOnly || len(cookies[1].Value) != 32 {
				t.Fatalf("cookies: %v", cookies)
			}
			if w.Header().Get("Vary") != "Cookie" {
				t.Fatal("missing Vary")
			}
			request := httptest.NewRequest("POST", "/logout", nil)
			request.AddCookie(cookies[0])
			out := httptest.NewRecorder()
			if err = m.Logout(out, request); err != nil {
				t.Fatal(err)
			}
			if _, ok := s.rows[next]; ok {
				t.Fatal("logout retained row")
			}
			if out.Result().Cookies()[0].MaxAge != -1 {
				t.Fatal("cookie not deleted")
			}
		})
	}
}
func TestLoginFailuresAndCollision(t *testing.T) {
	m, s, u := testLoginManager()
	s.collision = true
	if _, err := m.Login(httptest.NewRecorder(), httptest.NewRequest("POST", "/", nil), u); err != nil {
		t.Fatal(err)
	}
	s.interrupted = true
	w := httptest.NewRecorder()
	if _, err := m.Login(w, httptest.NewRequest("POST", "/", nil), u); !errors.Is(err, ErrSessionInterrupted) {
		t.Fatal(err)
	}
	if len(w.Result().Cookies()) != 0 {
		t.Fatal("cookies emitted before successful save")
	}
	u.IsActive = false
	if _, err := m.Login(w, httptest.NewRequest("POST", "/", nil), u); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal(err)
	}
}
func TestLoginExpiryAndCSRFSession(t *testing.T) {
	for _, expiry := range []any{nil, float64(0), float64(120), time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)} {
		m, s, u := testLoginManager()
		m.CSRFUseSessions = true
		data := map[string]any{"_session_expiry": expiry}
		raw, _ := EncodeSession(data, opts)
		old := "abcdefghijklmnopqrstuvwxyz012345"
		s.rows[old] = SessionRecord{Data: raw, ExpiresAt: time.Now().Add(time.Hour)}
		r := httptest.NewRequest("POST", "/", nil)
		r.AddCookie(&http.Cookie{Name: "sessionid", Value: old})
		w := httptest.NewRecorder()
		next, err := m.Login(w, r, u)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := DecodeSession(s.rows[next].Data, opts)
		csrf, _ := got["_csrftoken"].(string)
		if len(csrf) != 32 {
			t.Fatal("missing CSRF secret")
		}
		c := w.Result().Cookies()
		if len(c) != 1 {
			t.Fatal("CSRF cookie emitted with CSRF_USE_SESSIONS")
		}
		if expiry == float64(0) && (!c[0].Expires.IsZero() || c[0].MaxAge != 0) {
			t.Fatal("browser-close cookie has expiry")
		}
		if expiry == float64(120) && c[0].MaxAge != 120 {
			t.Fatalf("expiry %v", c[0])
		}
	}
}

func TestLoginCookieSettingsAndHook(t *testing.T) {
	m, s, u := testLoginManager()
	sc := DefaultSessionCookie()
	sc.Name = "customsession"
	sc.Path = "/app"
	sc.Domain = "example.test"
	sc.Secure = true
	sc.SameSite = http.SameSiteStrictMode
	cc := DefaultCSRFCookie()
	cc.Name = "customcsrf"
	cc.Secure = true
	m.SessionCookie = &sc
	m.CSRFCookie = &cc
	calls := 0
	m.AfterLogin = func(_ context.Context, user *AuthUser) error {
		calls++
		if user.ID != u.ID || len(s.rows) != 1 {
			t.Fatal("hook ran before save")
		}
		return nil
	}
	w := httptest.NewRecorder()
	_, err := m.Login(w, httptest.NewRequest("POST", "https://example.test/app/login", nil), u)
	if err != nil {
		t.Fatal(err)
	}
	c := w.Result().Cookies()
	if calls != 1 || c[0].Name != sc.Name || c[0].Path != sc.Path || c[0].Domain != sc.Domain || !c[0].Secure || c[0].SameSite != http.SameSiteStrictMode || c[1].Name != cc.Name {
		t.Fatalf("custom cookies: %v", c)
	}
	m.AfterLogin = func(context.Context, *AuthUser) error { return errors.New("hook failed") }
	w = httptest.NewRecorder()
	if _, err = m.Login(w, httptest.NewRequest("POST", "/", nil), u); err == nil {
		t.Fatal("hook failure ignored")
	}
	if len(w.Result().Cookies()) != 0 {
		t.Fatal("cookies emitted on hook failure")
	}
	sc.Name = "invalid cookie"
	before := len(s.rows)
	if _, err = m.Login(httptest.NewRecorder(), httptest.NewRequest("POST", "/", nil), u); err == nil {
		t.Fatal("bad cookie configuration accepted")
	}
	if len(s.rows) != before {
		t.Fatal("saved before validating configuration")
	}
}

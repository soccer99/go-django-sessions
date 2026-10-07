package go_django_sessions

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"
)

// djangoVersions lists the pip specs that the tests run against.
// The last entry has no upper bound, so it is always the latest release.
var djangoVersions = []string{"django>=4.2,<4.3", "django>=5.2,<5.3", "django"}

// runDjango runs testdata/django_session.py with the given Django version through uv.
func runDjango(t *testing.T, spec string, args ...string) string {
	t.Helper()
	if _, err := exec.LookPath("uv"); err != nil {
		t.Skip("uv is not installed")
	}
	base := []string{"run", "-q", "--no-project", "--python", "3.12", "--with", spec,
		"python", "testdata/django_session.py", opts.SecretKey}
	out, err := exec.Command("uv", append(base, args...)...).Output()
	if err != nil {
		if failure, ok := err.(*exec.ExitError); ok {
			out = append(out, failure.Stderr...)
		}
		t.Fatalf("uv %s: %v\n%s", spec, err, out)
	}
	return strings.TrimSpace(string(out))
}

// Compare full authentication decisions with Django's real database session
// store, ModelBackend and get_user, not just our own implementation's vectors.
func TestDjangoAuthentication(t *testing.T) {
	for _, spec := range djangoVersions {
		t.Run(spec, func(t *testing.T) {
			var cases []struct {
				Name          string    `json:"name"`
				Key           string    `json:"key"`
				Data          string    `json:"data"`
				Expires       time.Time `json:"expires"`
				UserID        string    `json:"user_id"`
				Password      string    `json:"password"`
				Active        bool      `json:"active"`
				UserExists    bool      `json:"user_exists"`
				SessionExists bool      `json:"session_exists"`
				Backends      []string  `json:"backends"`
				Authenticated bool      `json:"authenticated"`
			}
			if err := json.Unmarshal([]byte(runDjango(t, spec, "auth_cases")), &cases); err != nil {
				t.Fatal(err)
			}
			for _, c := range cases {
				t.Run(c.Name, func(t *testing.T) {
					backends := c.Backends
					// An empty configuration is a configuration error in Go.
					// Use a nonmatching entry to test removed ModelBackend.
					if len(backends) == 0 {
						backends = []string{"other.Backend"}
					}
					a := Authenticator{Options: opts, AuthenticationBackends: backends,
						LoadSession: func(context.Context, string) (*SessionRecord, error) {
							if !c.SessionExists {
								return nil, nil
							}
							return &SessionRecord{Data: c.Data, ExpiresAt: c.Expires}, nil
						},
						LoadUser: func(context.Context, string) (*AuthUser, error) {
							if !c.UserExists {
								return nil, nil
							}
							return &AuthUser{ID: c.UserID, Password: c.Password, IsActive: c.Active}, nil
						},
					}
					identity, err := a.Authenticate(context.Background(), c.Key)
					if (err == nil) != c.Authenticated {
						t.Fatalf("Django authenticated=%v; Go identity=%v err=%v", c.Authenticated, identity, err)
					}
					if !c.Authenticated && !errors.Is(err, ErrUnauthenticated) {
						t.Fatal(err)
					}
				})
			}
		})
	}
}

func TestDjangoVersions(t *testing.T) {
	want, _ := json.Marshal(longData)
	for _, spec := range djangoVersions {
		t.Run(spec, func(t *testing.T) {
			t.Logf("Django %s", runDjango(t, spec, "version"))

			// Django's real user method must agree with the Go auth hash.
			password := "pbkdf2_sha256$600000$salt$encoded"
			hash := runDjango(t, spec, "auth_hash", password)
			if hash != SessionAuthHash(password, opts.SecretKey) {
				t.Fatalf("authentication hash mismatch: Django=%s Go=%s", hash, SessionAuthHash(password, opts.SecretKey))
			}
			auth, record, _, _ := authFixture(t)
			payload, _ := json.Marshal(map[string]any{
				"_auth_user_id": "1", "_auth_user_backend": ModelBackend, "_auth_user_hash": hash,
			})
			record.Data = runDjango(t, spec, "encode", string(payload))
			if _, err := auth.Authenticate(context.Background(), testSessionKey); err != nil {
				t.Fatalf("authenticate Django session: %v", err)
			}

			// Django encodes, Go decodes.
			got, err := DecodeSession(runDjango(t, spec, "encode", string(want)), opts)
			if err != nil || !reflect.DeepEqual(got, longData) {
				t.Fatalf("Go decode of Django output: %v %v", got, err)
			}

			// Go encodes, Django decodes.
			enc, err := EncodeSession(longData, opts)
			if err != nil {
				t.Fatal(err)
			}
			var back map[string]any
			if err := json.Unmarshal([]byte(runDjango(t, spec, "decode", enc)), &back); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(back, longData) {
				t.Fatalf("Django decode of Go output: %v", back)
			}
		})
	}
}

// This exercises a real django_session row and Django's get_user(), rather than
// merely checking whether the JSON can be decoded.
func TestDjangoRecognizesGoLogin(t *testing.T) {
	for _, spec := range djangoVersions {
		t.Run(spec, func(t *testing.T) {
			m, s, user := testLoginManager()
			key, err := m.Login(httptest.NewRecorder(), httptest.NewRequest("POST", "/login", nil), user)
			if err != nil {
				t.Fatal(err)
			}
			var result struct {
				ID                  string `json:"id"`
				Hash                string `json:"hash"`
				AfterPasswordChange bool   `json:"after_password_change"`
			}
			out := runDjango(t, spec, "authenticate", key, s.rows[key].Data, user.Password)
			if err = json.Unmarshal([]byte(out), &result); err != nil {
				t.Fatal(err)
			}
			if result.ID != user.ID || result.Hash != SessionAuthHash(user.Password, opts.SecretKey) || result.AfterPasswordChange {
				t.Fatalf("Django rejected auth semantics: %+v", result)
			}
		})
	}
}

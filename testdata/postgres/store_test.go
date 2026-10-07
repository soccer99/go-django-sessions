package pgcheck

import (
	"context"
	"database/sql"
	"errors"
	_ "github.com/lib/pq"
	sessions "github.com/soccer99/go-django-sessions"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestPostgreSQLLoginStore(t *testing.T) {
	dsn := os.Getenv("DJANGO_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set DJANGO_TEST_POSTGRES_DSN to run PostgreSQL integration tests")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	_, err = db.Exec("CREATE TEMP TABLE django_session (session_key varchar(40) PRIMARY KEY, session_data text NOT NULL, expire_date timestamptz NOT NULL)")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	store := sessions.PostgreSQLStore{DB: db}
	oldKey := "abcdefghijklmnopqrstuvwxyz012345"
	next := "012345abcdefghijklmnopqrstuvwxyz"
	r := &sessions.SessionRecord{Data: "old", ExpiresAt: time.Now().UTC().Truncate(time.Microsecond).Add(time.Hour)}
	if err = store.Commit(ctx, "", oldKey, nil, r); err != nil {
		t.Fatal(err)
	}
	if err = store.Commit(ctx, "", oldKey, nil, r); !errors.Is(err, sessions.ErrSessionCollision) {
		t.Fatalf("collision %v", err)
	}
	loaded, err := store.Load(ctx, oldKey)
	if err != nil || loaded.Data != "old" {
		t.Fatalf("load %v %v", loaded, err)
	}
	changed := &sessions.SessionRecord{Data: "new", ExpiresAt: r.ExpiresAt}
	if err = store.Commit(ctx, oldKey, oldKey, loaded, changed); err != nil {
		t.Fatal(err)
	}
	if err = store.Commit(ctx, oldKey, next, loaded, changed); !errors.Is(err, sessions.ErrSessionInterrupted) {
		t.Fatalf("changed row %v", err)
	}
	if row, _ := store.Load(ctx, next); row != nil {
		t.Fatal("failed rotation inserted a row")
	}
	loaded, _ = store.Load(ctx, oldKey)
	if err = store.Commit(ctx, "", next, nil, r); err != nil {
		t.Fatal(err)
	}
	if err = store.Commit(ctx, oldKey, next, loaded, changed); !errors.Is(err, sessions.ErrSessionCollision) {
		t.Fatalf("rotation collision %v", err)
	}
	if row, _ := store.Load(ctx, oldKey); row == nil || row.Data != "new" {
		t.Fatal("collision removed old row")
	}
	store.Delete(ctx, next)
	if err = store.Commit(ctx, oldKey, next, loaded, changed); err != nil {
		t.Fatal(err)
	}
	if row, _ := store.Load(ctx, oldKey); row != nil {
		t.Fatal("rotation retained old row")
	}
	loaded, _ = store.Load(ctx, next)
	store.Delete(ctx, next)
	if err = store.Commit(ctx, next, next, loaded, changed); !errors.Is(err, sessions.ErrSessionInterrupted) {
		t.Fatalf("deleted update %v", err)
	}
	if row, _ := store.Load(ctx, next); row != nil {
		t.Fatal("logout resurrected")
	}
	// Exercise login and logout using the actual adapter and database.
	m := sessions.LoginManager{Options: sessions.SessionOptions{SecretKey: "test"}, Store: store, AuthenticationBackends: []string{sessions.ModelBackend}}
	w := httptest.NewRecorder()
	key, err := m.Login(w, httptest.NewRequest("POST", "/", nil), &sessions.AuthUser{ID: "1", Password: "encoded", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	row, err := store.Load(ctx, key)
	if err != nil || row == nil {
		t.Fatal("login not saved", err)
	}
	data, err := sessions.DecodeSession(row.Data, m.Options)
	if err != nil || data["_auth_user_id"] != "1" {
		t.Fatal("bad login", err)
	}
	request := httptest.NewRequest("POST", "/", nil)
	request.AddCookie(&http.Cookie{Name: "sessionid", Value: key})
	if err = m.Logout(httptest.NewRecorder(), request); err != nil {
		t.Fatal(err)
	}
	if row, _ := store.Load(ctx, key); row != nil {
		t.Fatal("logout retained row")
	}
}

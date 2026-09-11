package go_django_sessions

import (
	"reflect"
	"testing"
)

var opts = SessionOptions{SecretKey: "test-secret-key-123"}

// Vectors produced by Django 4.2 SessionStore().encode(...).
const (
	djangoShort = "eyJfYXV0aF91c2VyX2lkIjoiMSJ9:1x4ueg:oQJ3C8ONteUuNquQXUQmN3yYApbdRO8U3a2CMErOp50"
	djangoLong  = ".eJyrVopPLC3JiC8tTi2Kz0xRslIyVNJBFktKTM5OzQNJpGQl5qXn6yXn55UUZSbpgZToQWWL9XzzU1JznKBqUQzISCzOAOpOTEoGiucpWZnqKOUoWUUb6hjF6iiVAmUyYkoNDFItc3LyFWyS7JRqAeOYMPo:1x4ueg:do9RPD43OY2oeYbJTHqNtLfAZvLOyhz7JvkwdbM6t4s"
)

var longData = map[string]any{
	"_auth_user_id":      "1",
	"_auth_user_backend": "django.contrib.auth.backends.ModelBackend",
	"_auth_user_hash":    "abc",
	"n":                  float64(5),
	"l":                  []any{float64(1), float64(2)},
	"u":                  "héllo <b>",
}

func TestDecodeDjango(t *testing.T) {
	got, err := DecodeSession(djangoShort, opts)
	if err != nil || !reflect.DeepEqual(got, map[string]any{"_auth_user_id": "1"}) {
		t.Fatalf("short: %v %v", got, err)
	}
	got, err = DecodeSession(djangoLong, opts)
	if err != nil || !reflect.DeepEqual(got, longData) {
		t.Fatalf("long (compressed): %v %v", got, err)
	}
}

func TestBadSignature(t *testing.T) {
	if _, err := DecodeSession(djangoShort, SessionOptions{SecretKey: "wrong"}); err != ErrInvalidSignature {
		t.Fatalf("want ErrInvalidSignature, got %v", err)
	}
	if _, err := DecodeSession(djangoShort[:len(djangoShort)-1]+"X", opts); err != ErrInvalidSignature {
		t.Fatalf("want ErrInvalidSignature, got %v", err)
	}
}

func TestRoundTrip(t *testing.T) {
	enc, err := EncodeSession(longData, opts)
	if err != nil {
		t.Fatal(err)
	}
	if enc[0] != '.' {
		t.Fatal("expected compressed output")
	}
	got, err := DecodeSession(enc, opts)
	if err != nil || !reflect.DeepEqual(got, longData) {
		t.Fatalf("roundtrip: %v %v", got, err)
	}
	if string(asciiJSON([]byte(`"é😀"`))) != `"\u00e9\ud83d\ude00"` {
		t.Fatal("asciiJSON mismatch")
	}
}

func TestB62(t *testing.T) {
	if b62(0) != "0" || b62(1789107754) != "1x4ueg" { // 1x4ueg is Django's b62 of 1789107754
		t.Fatalf("b62 mismatch: %s", b62(1789107754))
	}
}

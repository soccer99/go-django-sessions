// Package go_django_sessions encodes and decodes Django session data.
// It supports django.contrib.sessions with the default JSON serializer.
package go_django_sessions

import (
	"bytes"
	"compress/zlib"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode/utf16"
)

// DefaultSalt is the salt that the Django SessionStore uses to sign session data.
const DefaultSalt = "django.contrib.sessions.SessionStore"

// ErrInvalidSignature is the error that DecodeSession returns when the signature does not match.
var ErrInvalidSignature = errors.New("invalid signature")

// SessionOptions holds the settings for EncodeSession and DecodeSession.
type SessionOptions struct {
	// SecretKey is the Django SECRET_KEY.
	// If it is empty, the library reads the DJANGO_SECRET_KEY environment variable.
	SecretKey string
	// Salt is the signing salt. If it is empty, the library uses DefaultSalt.
	Salt string
}

func (o SessionOptions) resolve() (key, salt string, err error) {
	key = o.SecretKey
	if key == "" {
		key = os.Getenv("DJANGO_SECRET_KEY")
	}
	if key == "" {
		return "", "", errors.New("no secret key: set SessionOptions.SecretKey or DJANGO_SECRET_KEY")
	}
	salt = o.Salt
	if salt == "" {
		salt = DefaultSalt
	}
	return key, salt, nil
}

// signature calculates the same HMAC-SHA256 signature as django.core.signing.Signer.
func signature(value, key, salt string) string {
	keyHash := sha256.Sum256([]byte(salt + "signer" + key))
	h := hmac.New(sha256.New, keyHash[:])
	h.Write([]byte(value))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// DecodeSession checks the signature of a session_data string and returns the session data.
// The string comes from the django_session table.
// JSON numbers become float64 values.
func DecodeSession(sessionData string, options SessionOptions) (map[string]any, error) {
	key, salt, err := options.resolve()
	if err != nil {
		return nil, err
	}

	i := strings.LastIndex(sessionData, ":")
	if i < 0 {
		return nil, ErrInvalidSignature
	}
	value, sig := sessionData[:i], sessionData[i+1:]
	if !hmac.Equal([]byte(sig), []byte(signature(value, key, salt))) {
		return nil, ErrInvalidSignature
	}

	// Remove the TimestampSigner timestamp. Django also ignores it. The expiry is in expire_date.
	if i := strings.LastIndex(value, ":"); i >= 0 {
		value = value[:i]
	}

	compressed := strings.HasPrefix(value, ".")
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, "."))
	if err != nil {
		return nil, err
	}
	if compressed {
		r, err := zlib.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		defer r.Close()
		if data, err = io.ReadAll(r); err != nil {
			return nil, err
		}
	}

	var result map[string]any
	return result, json.Unmarshal(data, &result)
}

// EncodeSession converts session data to a signed string that Django can read.
// The output has the same format as SessionStore.encode.
func EncodeSession(data map[string]any, options SessionOptions) (string, error) {
	key, salt, err := options.resolve()
	if err != nil {
		return "", err
	}

	raw, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	raw = asciiJSON(raw)

	var zbuf bytes.Buffer
	zw := zlib.NewWriter(&zbuf)
	zw.Write(raw)
	zw.Close()

	value := base64.RawURLEncoding.EncodeToString(raw)
	if zbuf.Len() < len(raw)-1 { // Django uses the same limit.
		value = "." + base64.RawURLEncoding.EncodeToString(zbuf.Bytes())
	}
	value += ":" + b62(time.Now().Unix())
	return value + ":" + signature(value, key, salt), nil
}

// asciiJSON replaces non-ASCII characters with JSON escape sequences.
// This is the same as Python json.dumps with ensure_ascii=True.
// Django reads session JSON as latin-1. Raw UTF-8 bytes would become incorrect characters.
func asciiJSON(b []byte) []byte {
	var out strings.Builder
	for _, r := range string(b) {
		switch {
		case r < 0x80:
			out.WriteRune(r)
		case r < 0x10000:
			fmt.Fprintf(&out, `\u%04x`, r)
		default:
			hi, lo := utf16.EncodeRune(r)
			fmt.Fprintf(&out, `\u%04x\u%04x`, hi, lo)
		}
	}
	return []byte(out.String())
}

const b62Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// b62 encodes a non-negative integer in the same base-62 format as django.core.signing.b62_encode.
func b62(n int64) string {
	if n == 0 {
		return "0"
	}
	var s []byte
	for ; n > 0; n /= 62 {
		s = append([]byte{b62Alphabet[n%62]}, s...)
	}
	return string(s)
}

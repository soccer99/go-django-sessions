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
)

const DefaultSalt = "django.contrib.sessions.SessionStore"

// SessionOptions contains configuration options for the decoder
type SessionOptions struct {
	SecretKey string
	Salt      string
}

// calculateSignature computes the HMAC signature for Django session data
func calculateSignature(value, key, salt string) (string, error) {
	keyData := []byte(fmt.Sprintf("%ssigner%s", salt, key))
	keyHash := sha256.Sum256(keyData)

	h := hmac.New(sha256.New, keyHash[:])
	h.Write([]byte(value))
	signature := h.Sum(nil)

	base64Sig := base64.StdEncoding.EncodeToString(signature)
	// Replace characters for URL safety, similar to Django's base64 handling
	base64Sig = strings.ReplaceAll(base64Sig, "+", "-")
	base64Sig = strings.ReplaceAll(base64Sig, "/", "_")
	base64Sig = strings.ReplaceAll(base64Sig, "=", "")

	return base64Sig, nil
}

// decodeBase64 decodes a modified base64 string (with URL-safe characters)
func decodeBase64(s string) ([]byte, error) {
	// Split at colon if present (format used in the original code)
	parts := strings.SplitN(s, ":", 2)
	s = parts[0]

	// Add padding if needed
	mod := len(s) % 4
	if mod != 0 {
		s += strings.Repeat("=", 4-mod)
	}

	// Convert URL-safe characters back to standard base64
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")

	return base64.StdEncoding.DecodeString(s)
}

// verifyAndExtractData checks the signature and returns the data portion
func verifyAndExtractData(signedValue, key, salt string) (string, error) {
	lastColon := strings.LastIndex(signedValue, ":")
	if lastColon == -1 {
		return "", errors.New("no signature delimiter found")
	}

	value := signedValue[:lastColon]
	signature := signedValue[lastColon+1:]
	expectedSignature, err := calculateSignature(value, key, salt)
	if err != nil {
		return "", err
	}

	if signature != expectedSignature {
		return "", errors.New("invalid signature")
	}

	return value, nil
}

// DecodeSession decodes a Django session and returns the data as an interface{}
func DecodeSession(sessionData string, options SessionOptions) (map[string]string, error) {
	secretKey := options.SecretKey
	if secretKey == "" {
		secretKey = os.Getenv("DJANGO_SECRET_KEY")
		if secretKey == "" {
			return nil, errors.New("no secret key provided. Pass it in the options param under key 'SecretKey' or set DJANGO_SECRET_KEY environment variable")
		}
	}

	salt := options.Salt
	if salt == "" {
		salt = DefaultSalt
	}

	value, err := verifyAndExtractData(sessionData, secretKey, salt)
	if err != nil {
		return nil, err
	}

	isCompressed := strings.HasPrefix(value, ".")
	b64Data := value
	if isCompressed {
		b64Data = value[1:]
	}

	data, err := decodeBase64(b64Data)
	if err != nil {
		return nil, err
	}

	if isCompressed {
		reader, err := zlib.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		defer reader.Close()

		decompressed, err := io.ReadAll(reader)
		if err != nil {
			return nil, err
		}
		data = decompressed
	}

	var result map[string]string
	err = json.Unmarshal(data, &result)
	return result, err
}

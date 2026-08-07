// Package proxy implements a minimal, stateless reverse proxy that streams
// a single S3 object per request and answers with CORS headers the proxy
// itself controls. It never makes an authorization decision beyond
// verifying a token minted elsewhere (the upstream application); it has no
// database, no session state, and no knowledge of who the requesting user
// is.
package proxy

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"time"
)

var (
	ErrMalformedToken   = errors.New("malformed token")
	ErrInvalidSignature = errors.New("invalid token signature")
	ErrExpiredToken     = errors.New("token expired")
)

// Token is the verified, decoded form of a signed handoff grant: permission
// to stream exactly one bucket/key until Expiry.
type Token struct {
	Bucket string
	Key    string
	Expiry time.Time
}

// Sign produces a "bucket.key.expUnix.sig" token authorizing a GET of the
// given bucket/key until expiry. The upstream application (not this
// service) is the one that calls Sign, after it has already run its own
// authorization checks — this function exists in the proxy's codebase
// mainly so tests and the upstream's Go tooling, if any, can produce
// tokens Verify accepts.
func Sign(secret []byte, bucket, key string, expiry time.Time) string {
	payload := signingPayload(bucket, key, expiry)
	return payload + "." + macFor(secret, payload)
}

// Verify checks a token's signature and expiry and, if valid, returns the
// bucket/key it authorizes.
func Verify(secret []byte, token string) (Token, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 4 {
		return Token{}, ErrMalformedToken
	}
	payload := strings.Join(parts[:3], ".")

	want := macFor(secret, payload)
	if subtle.ConstantTimeCompare([]byte(parts[3]), []byte(want)) != 1 {
		return Token{}, ErrInvalidSignature
	}

	bucket, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Token{}, ErrMalformedToken
	}
	key, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Token{}, ErrMalformedToken
	}
	expUnix, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return Token{}, ErrMalformedToken
	}

	expiry := time.Unix(expUnix, 0)
	if time.Now().After(expiry) {
		return Token{}, ErrExpiredToken
	}

	return Token{Bucket: string(bucket), Key: string(key), Expiry: expiry}, nil
}

func signingPayload(bucket, key string, expiry time.Time) string {
	b := base64.RawURLEncoding.EncodeToString([]byte(bucket))
	k := base64.RawURLEncoding.EncodeToString([]byte(key))
	exp := strconv.FormatInt(expiry.Unix(), 10)
	return strings.Join([]string{b, k, exp}, ".")
}

func macFor(secret []byte, payload string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

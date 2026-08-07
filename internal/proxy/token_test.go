package proxy

import (
	"errors"
	"testing"
	"time"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	secret := []byte("test-secret")
	expiry := time.Now().Add(time.Hour).Truncate(time.Second)

	tok := Sign(secret, "my-bucket", "path/to/some file.laz", expiry)

	claim, err := Verify(secret, tok)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if claim.Bucket != "my-bucket" {
		t.Errorf("Bucket = %q, want %q", claim.Bucket, "my-bucket")
	}
	if claim.Key != "path/to/some file.laz" {
		t.Errorf("Key = %q, want %q", claim.Key, "path/to/some file.laz")
	}
	if !claim.Expiry.Equal(expiry) {
		t.Errorf("Expiry = %v, want %v", claim.Expiry, expiry)
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	secret := []byte("test-secret")
	tok := Sign(secret, "bucket", "key", time.Now().Add(-time.Minute))

	if _, err := Verify(secret, tok); !errors.Is(err, ErrExpiredToken) {
		t.Fatalf("err = %v, want ErrExpiredToken", err)
	}
}

func TestVerifyRejectsTamperedSignature(t *testing.T) {
	secret := []byte("test-secret")
	tok := Sign(secret, "bucket", "key", time.Now().Add(time.Hour))
	tampered := tok[:len(tok)-1] + "x"

	if _, err := Verify(secret, tampered); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("err = %v, want ErrInvalidSignature", err)
	}
}

func TestVerifyRejectsWrongSecret(t *testing.T) {
	tok := Sign([]byte("secret-a"), "bucket", "key", time.Now().Add(time.Hour))

	if _, err := Verify([]byte("secret-b"), tok); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("err = %v, want ErrInvalidSignature", err)
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	if _, err := Verify([]byte("secret"), "not-a-real-token"); !errors.Is(err, ErrMalformedToken) {
		t.Fatalf("err = %v, want ErrMalformedToken", err)
	}
}

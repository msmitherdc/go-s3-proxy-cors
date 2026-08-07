package proxy

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type fakeS3 struct {
	lastInput *s3.GetObjectInput
	body      string
	err       error
}

func (f *fakeS3) GetObject(_ context.Context, params *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	f.lastInput = params
	if f.err != nil {
		return nil, f.err
	}
	return &s3.GetObjectOutput{
		Body:          io.NopCloser(bytes.NewBufferString(f.body)),
		ContentLength: aws.Int64(int64(len(f.body))),
	}, nil
}

func testHandler(fake *fakeS3) *Handler {
	return &Handler{
		Secret:         []byte("test-secret"),
		S3:             fake,
		AllowedOrigins: NewAllowlist("https://griddl.example.mil"),
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func TestPreflight(t *testing.T) {
	h := testHandler(&fakeS3{})
	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set("Origin", "https://griddl.example.mil")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://griddl.example.mil" {
		t.Errorf("Access-Control-Allow-Origin = %q", got)
	}
}

func TestDisallowedOrigin(t *testing.T) {
	h := testHandler(&fakeS3{})
	tok := Sign(h.Secret, "bucket", "key", time.Now().Add(time.Hour))
	req := httptest.NewRequest(http.MethodGet, "/?token="+tok, nil)
	req.Header.Set("Origin", "https://evil.example.com")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Access-Control-Allow-Origin should be unset for a disallowed origin, got %q", got)
	}
}

func TestMissingToken(t *testing.T) {
	h := testHandler(&fakeS3{})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://griddl.example.mil")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestExpiredToken(t *testing.T) {
	h := testHandler(&fakeS3{})
	tok := Sign(h.Secret, "bucket", "key", time.Now().Add(-time.Minute))
	req := httptest.NewRequest(http.MethodGet, "/?token="+tok, nil)
	req.Header.Set("Origin", "https://griddl.example.mil")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusGone {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusGone)
	}
}

func TestSuccessfulStream(t *testing.T) {
	fake := &fakeS3{body: "hello world"}
	h := testHandler(fake)
	tok := Sign(h.Secret, "my-bucket", "my/key.laz", time.Now().Add(time.Hour))
	req := httptest.NewRequest(http.MethodGet, "/?token="+tok, nil)
	req.Header.Set("Origin", "https://griddl.example.mil")
	req.Header.Set("Range", "bytes=0-4")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if rec.Body.String() != "hello world" {
		t.Errorf("body = %q", rec.Body.String())
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://griddl.example.mil" {
		t.Errorf("Access-Control-Allow-Origin = %q", got)
	}
	if fake.lastInput == nil || aws.ToString(fake.lastInput.Bucket) != "my-bucket" {
		t.Fatalf("bucket forwarded = %v", fake.lastInput)
	}
	if aws.ToString(fake.lastInput.Key) != "my/key.laz" {
		t.Errorf("key forwarded = %q", aws.ToString(fake.lastInput.Key))
	}
	if aws.ToString(fake.lastInput.Range) != "bytes=0-4" {
		t.Errorf("range forwarded = %q, want %q", aws.ToString(fake.lastInput.Range), "bytes=0-4")
	}
}

func TestHeadRequestOmitsBody(t *testing.T) {
	fake := &fakeS3{body: "hello world"}
	h := testHandler(fake)
	tok := Sign(h.Secret, "my-bucket", "my/key.laz", time.Now().Add(time.Hour))
	req := httptest.NewRequest(http.MethodHead, "/?token="+tok, nil)
	req.Header.Set("Origin", "https://griddl.example.mil")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("HEAD response body = %q, want empty", rec.Body.String())
	}
}

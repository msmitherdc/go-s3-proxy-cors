package proxy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// S3GetObjectAPI is the slice of *s3.Client this proxy actually calls.
// Narrowing it to one method keeps the handler testable without a real S3
// endpoint.
type S3GetObjectAPI interface {
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

// Handler streams one S3 object per request, authorized by a signed Token
// in the "token" query parameter, and answers with CORS headers scoped to
// AllowedOrigins. It holds no state across requests and makes no
// authorization decision beyond verifying that token.
type Handler struct {
	Secret         []byte
	S3             S3GetObjectAPI
	AllowedOrigins Allowlist
	Logger         *slog.Logger
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	allowed := h.AllowedOrigins.Allowed(origin)
	if allowed {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Vary", "Origin")
	}

	if r.Method == http.MethodOptions {
		h.preflight(w)
		return
	}

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !allowed {
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return
	}

	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "missing token", http.StatusBadRequest)
		return
	}

	claim, err := Verify(h.Secret, token)
	if err != nil {
		h.Logger.Warn("token rejected", "error", err)
		status := http.StatusForbidden
		if errors.Is(err, ErrExpiredToken) {
			status = http.StatusGone
		}
		http.Error(w, "invalid token", status)
		return
	}

	input := &s3.GetObjectInput{
		Bucket: aws.String(claim.Bucket),
		Key:    aws.String(claim.Key),
	}
	if rng := r.Header.Get("Range"); rng != "" {
		input.Range = aws.String(rng)
	}

	out, err := h.S3.GetObject(r.Context(), input)
	if err != nil {
		h.Logger.Error("s3 GetObject failed", "bucket", claim.Bucket, "key", claim.Key, "error", err)
		http.Error(w, "upstream fetch failed", http.StatusBadGateway)
		return
	}
	defer out.Body.Close()

	h.writeObjectHeaders(w, out)

	status := http.StatusOK
	if out.ContentRange != nil {
		status = http.StatusPartialContent
	}
	w.WriteHeader(status)

	if r.Method == http.MethodHead {
		return
	}
	if _, err := io.Copy(w, out.Body); err != nil {
		h.Logger.Warn("stream interrupted", "bucket", claim.Bucket, "key", claim.Key, "error", err)
	}
}

func (h *Handler) preflight(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Range")
	w.Header().Set("Access-Control-Expose-Headers", "Content-Range, Accept-Ranges, Content-Length, ETag")
	w.Header().Set("Access-Control-Max-Age", "3600")
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) writeObjectHeaders(w http.ResponseWriter, out *s3.GetObjectOutput) {
	if out.ContentType != nil {
		w.Header().Set("Content-Type", *out.ContentType)
	}
	if out.ContentRange != nil {
		w.Header().Set("Content-Range", *out.ContentRange)
	}
	if out.ContentLength != nil {
		w.Header().Set("Content-Length", strconv.FormatInt(*out.ContentLength, 10))
	}
	if out.ETag != nil {
		w.Header().Set("ETag", *out.ETag)
	}
	w.Header().Set("Accept-Ranges", "bytes")
}

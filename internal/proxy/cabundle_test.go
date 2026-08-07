package proxy

import (
	"context"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
)

func TestParseS3URI(t *testing.T) {
	tests := []struct {
		uri        string
		wantBucket string
		wantKey    string
		wantErr    bool
	}{
		{"s3://my-bucket/path/to/bundle.pem", "my-bucket", "path/to/bundle.pem", false},
		{"s3://my-bucket/", "", "", true},
		{"s3:///key", "", "", true},
		{"https://example.com/bundle.pem", "", "", true},
		{"my-bucket/key", "", "", true},
	}
	for _, tt := range tests {
		bucket, key, err := ParseS3URI(tt.uri)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParseS3URI(%q) expected error, got none", tt.uri)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseS3URI(%q) unexpected error: %v", tt.uri, err)
			continue
		}
		if bucket != tt.wantBucket || key != tt.wantKey {
			t.Errorf("ParseS3URI(%q) = (%q, %q), want (%q, %q)", tt.uri, bucket, key, tt.wantBucket, tt.wantKey)
		}
	}
}

func TestFetchCABundle(t *testing.T) {
	fake := &fakeS3{body: "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----"}

	got, err := FetchCABundle(context.Background(), fake, "my-bucket", "certs/bundle.pem")
	if err != nil {
		t.Fatalf("FetchCABundle() error = %v", err)
	}
	if string(got) != fake.body {
		t.Errorf("FetchCABundle() = %q, want %q", got, fake.body)
	}
	if aws.ToString(fake.lastInput.Bucket) != "my-bucket" || aws.ToString(fake.lastInput.Key) != "certs/bundle.pem" {
		t.Errorf("unexpected request: %v", fake.lastInput)
	}
}

func TestFetchCABundleError(t *testing.T) {
	fake := &fakeS3{err: errors.New("access denied")}

	if _, err := FetchCABundle(context.Background(), fake, "my-bucket", "certs/bundle.pem"); err == nil {
		t.Fatal("expected error")
	}
}

func TestHTTPClientWithCABundleTrustsProvidedCA(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	// Sanity check: the default client (no custom pool) should NOT trust
	// this test server's self-signed cert.
	if _, err := http.DefaultClient.Get(server.URL); err == nil {
		t.Fatal("expected default client to reject the test server's self-signed cert")
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})

	client, err := HTTPClientWithCABundle(pemBytes)
	if err != nil {
		t.Fatalf("HTTPClientWithCABundle() error = %v", err)
	}

	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		t.Errorf("body = %q, want %q", body, "ok")
	}
}

func TestHTTPClientWithCABundleRejectsGarbage(t *testing.T) {
	if _, err := HTTPClientWithCABundle([]byte("not a certificate")); err == nil {
		t.Fatal("expected error for a bundle with no certificates")
	}
}

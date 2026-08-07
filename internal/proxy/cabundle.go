package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// ParseS3URI splits an "s3://bucket/key" URI into its parts.
func ParseS3URI(uri string) (bucket, key string, err error) {
	const prefix = "s3://"
	if !strings.HasPrefix(uri, prefix) {
		return "", "", fmt.Errorf("CA bundle URI must start with %q, got %q", prefix, uri)
	}
	bucket, key, found := strings.Cut(strings.TrimPrefix(uri, prefix), "/")
	if !found || bucket == "" || key == "" {
		return "", "", fmt.Errorf("CA bundle URI must be s3://bucket/key, got %q", uri)
	}
	return bucket, key, nil
}

// FetchCABundle downloads a PEM-encoded CA bundle object via s3Client.
// This call itself goes out over whatever trust store s3Client's HTTP
// client already has (the host's normal system trust) - it's meant for
// networks where the bundle's own bucket is reachable that way, not a
// bootstrap of trust from nothing.
func FetchCABundle(ctx context.Context, s3Client S3GetObjectAPI, bucket, key string) ([]byte, error) {
	out, err := s3Client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	if err != nil {
		return nil, fmt.Errorf("fetching CA bundle s3://%s/%s: %w", bucket, key, err)
	}
	defer out.Body.Close()

	pemBytes, err := io.ReadAll(out.Body)
	if err != nil {
		return nil, fmt.Errorf("reading CA bundle s3://%s/%s: %w", bucket, key, err)
	}
	return pemBytes, nil
}

// HTTPClientWithCABundle returns an *http.Client that trusts the host's
// normal system CA pool plus the certificates in pemBytes. Intended to
// be set as an S3 client's HTTPClient so every subsequent call - not
// just the bundle fetch itself - trusts certificates issued by that
// bundle's CA (e.g. an internal PKI root used on a classified network,
// not present in a distroless image's default trust store).
func HTTPClientWithCABundle(pemBytes []byte) (*http.Client, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, errors.New("no certificates found in CA bundle")
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: pool}
	return &http.Client{Transport: transport}, nil
}

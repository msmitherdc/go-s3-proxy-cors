// Command go-s3-proxy-cors runs the CORS-fallback S3 streaming proxy.
//
// Required environment variables:
//
//	PROXY_HMAC_SECRET   shared secret used to verify handoff tokens
//	ALLOWED_ORIGINS     comma-separated list of origins to echo back in
//	                     Access-Control-Allow-Origin
//
// Optional:
//
//	LISTEN_ADDR         address to listen on (default ":8080")
//	CA_BUNDLE_S3_URI    s3://bucket/key of a PEM CA bundle to trust in
//	                     addition to the host's system pool, for
//	                     networks with an internal PKI root not present
//	                     in the image's default trust store
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/msmitherdc/go-s3-proxy-cors/internal/proxy"
)

// version is stamped in by goreleaser at build time (-X main.version=...).
var version = "dev"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	secret := os.Getenv("PROXY_HMAC_SECRET")
	origins := os.Getenv("ALLOWED_ORIGINS")
	if secret == "" || origins == "" {
		logger.Error("PROXY_HMAC_SECRET and ALLOWED_ORIGINS are required")
		os.Exit(1)
	}

	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	ctx := context.Background()

	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		logger.Error("failed to load AWS config", "error", err)
		os.Exit(1)
	}

	s3Client := s3.NewFromConfig(awsCfg)
	if caBundleURI := os.Getenv("CA_BUNDLE_S3_URI"); caBundleURI != "" {
		s3Client, err = s3ClientWithCABundle(ctx, awsCfg, s3Client, caBundleURI)
		if err != nil {
			logger.Error("failed to load CA bundle", "uri", caBundleURI, "error", err)
			os.Exit(1)
		}
	}

	handler := &proxy.Handler{
		Secret:         []byte(secret),
		S3:             s3Client,
		AllowedOrigins: proxy.NewAllowlist(origins),
		Logger:         logger,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.Handle("/", handler)

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	logger.Info("starting go-s3-proxy-cors", "version", version, "addr", addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("server error", "error", err)
		os.Exit(1)
	}
}

// s3ClientWithCABundle fetches the PEM CA bundle at uri using bootstrap
// (the default-trust S3 client) and returns a new S3 client whose HTTP
// transport also trusts that bundle's CA - used for every call the
// returned client makes afterward, not just this fetch.
func s3ClientWithCABundle(ctx context.Context, cfg aws.Config, bootstrap *s3.Client, uri string) (*s3.Client, error) {
	bucket, key, err := proxy.ParseS3URI(uri)
	if err != nil {
		return nil, err
	}

	pemBytes, err := proxy.FetchCABundle(ctx, bootstrap, bucket, key)
	if err != nil {
		return nil, err
	}

	httpClient, err := proxy.HTTPClientWithCABundle(pemBytes)
	if err != nil {
		return nil, err
	}

	return s3.NewFromConfig(cfg, func(o *s3.Options) { o.HTTPClient = httpClient }), nil
}

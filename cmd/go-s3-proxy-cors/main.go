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
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"time"

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

	awsCfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		logger.Error("failed to load AWS config", "error", err)
		os.Exit(1)
	}

	handler := &proxy.Handler{
		Secret:         []byte(secret),
		S3:             s3.NewFromConfig(awsCfg),
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

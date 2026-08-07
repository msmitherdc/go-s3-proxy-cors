# go-s3-proxy-cors

A minimal, stateless Go proxy that streams a single S3 object per request
and answers with CORS headers it controls itself.

## Why this exists

Presigned S3 URLs are the normal, cheap path for browser downloads: the
client fetches the object directly from S3, no app-tier bandwidth spent.
That only works when the source bucket has CORS configured for the
requesting origin — which the app can't guarantee for every bucket, e.g.
external public datasets or another organization's bucket it doesn't own.
Rather than route every download through the app tier "just in case" (which
ties download throughput and connection count to whatever's sized for API
traffic), this proxy exists purely as the fallback for buckets whose CORS
can't be relied on: the client tries the direct presigned URL first, and
only on a CORS failure does it retry through this proxy instead.

Because it's a rare fallback path rather than the primary transport, it's
built to run as a small, independently-scaled service (e.g. an ECS Fargate
service near zero desired count) rather than live inside the main app.

## What it does — and doesn't — do

- Verifies a short-lived, HMAC-signed token (minted by the upstream
  application, *not* by this service) that authorizes exactly one
  bucket/key until an expiry.
- Streams that object from S3 to the client, forwarding `Range` requests.
- Sets CORS response headers based on a fixed origin allowlist it's
  configured with — regardless of whether the *source* bucket has CORS
  configured at all.

It does **not** have a database, a session store, or any notion of who the
requesting user is. All authorization happens upstream, before a token is
ever minted; this service only checks that the token is genuine and
unexpired. It also does not decide which downloads should use it — that
routing decision belongs to the caller (retry-on-CORS-failure, or
pre-known-untrusted-bucket, or whatever policy the upstream app wants).

## Token format

```
<base64url(bucket)>.<base64url(key)>.<expiry_unix>.<base64url(hmac_sha256)>
```

The HMAC covers the first three dot-joined fields, keyed by
`PROXY_HMAC_SECRET`. See [`internal/proxy/token.go`](internal/proxy/token.go)
for the exact signing/verification logic — treat that file as the source of
truth for how a caller in another language should construct a token.

## Configuration

| Env var             | Required | Description                                              |
|----------------------|----------|-----------------------------------------------------------|
| `PROXY_HMAC_SECRET`  | yes      | Shared secret used to verify handoff tokens                |
| `ALLOWED_ORIGINS`    | yes      | Comma-separated origins to echo in `Access-Control-Allow-Origin` |
| `LISTEN_ADDR`        | no       | Listen address (default `:8080`)                            |

AWS credentials/region come from the standard SDK default chain (env vars,
instance/task role, etc.) — on ECS this should just be the task role, scoped
to `s3:GetObject` on whichever buckets it needs to reach.

## Endpoints

- `GET|HEAD /?token=...` — streams the object the token authorizes.
- `OPTIONS /` — CORS preflight response.
- `GET /healthz` — liveness/readiness check, no auth required.

## Running locally

```bash
export PROXY_HMAC_SECRET=dev-secret
export ALLOWED_ORIGINS=http://localhost:3000
go run ./cmd/go-s3-proxy-cors
```

## Building

```bash
go build ./...
go test ./...
```

Or via Docker:

```bash
docker build -t go-s3-proxy-cors .
```

Releases are built for `linux/amd64`, `linux/arm64`, `darwin/amd64`, and
`darwin/arm64` via [GoReleaser](https://goreleaser.com/), and a
multi-arch container image is pushed to
`ghcr.io/msmitherdc/go-s3-proxy-cors`. Versioning and the changelog are
managed by [release-please](https://github.com/googleapis/release-please)
from Conventional Commits on `main`.

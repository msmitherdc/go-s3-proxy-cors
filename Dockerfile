FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/go-s3-proxy-cors ./cmd/go-s3-proxy-cors

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/go-s3-proxy-cors /go-s3-proxy-cors
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/go-s3-proxy-cors"]

FROM golang:1.25 AS build
WORKDIR /src
COPY go.* ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /oidc-trust-audit ./cmd/oidc-trust-audit

# distroless/static runs as a non-root user and ships no shell.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /oidc-trust-audit /oidc-trust-audit
ENTRYPOINT ["/oidc-trust-audit"]

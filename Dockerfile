FROM golang:1.25-alpine AS build
WORKDIR /src

ARG VERSION=dev
COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ cmd/
COPY internal/ internal/
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /kryptic-operator ./cmd/kryptic-operator

# Distroless static: no shell, no package manager, runs as nonroot.
FROM gcr.io/distroless/static:nonroot
ARG VERSION=dev
LABEL org.opencontainers.image.source="https://github.com/dev-kryptic/Kryptic.K8s.Operator" \
      org.opencontainers.image.version="${VERSION}"
COPY --from=build /kryptic-operator /kryptic-operator
USER 65532:65532
ENTRYPOINT ["/kryptic-operator"]

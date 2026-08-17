FROM golang:1.24-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ cmd/
COPY internal/ internal/
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /kryptic-operator ./cmd/kryptic-operator

# Distroless static: no shell, no package manager, runs as nonroot.
FROM gcr.io/distroless/static:nonroot
COPY --from=build /kryptic-operator /kryptic-operator
USER 65532:65532
ENTRYPOINT ["/kryptic-operator"]

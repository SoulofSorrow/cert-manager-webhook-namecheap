FROM golang:1.21-alpine AS builder

WORKDIR /build

# Copy module files. go.sum is optional — generated if missing.
COPY go.mod go.su[m] ./

# Copy source first so go mod tidy can resolve actual imports
COPY . .

# Generate/refresh go.sum and download all dependencies
RUN go mod tidy && go mod download

RUN CGO_ENABLED=0 GOOS=linux go build -o webhook ./cmd/webhook

# ---

FROM alpine:3.19

RUN apk add --no-cache ca-certificates

COPY --from=builder /build/webhook /usr/local/bin/webhook

USER 65534:65534

ENTRYPOINT ["/usr/local/bin/webhook"]
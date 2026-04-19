FROM golang:1.21-alpine AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o webhook ./cmd/webhook

# ---

FROM alpine:3.19

RUN apk add --no-cache ca-certificates

COPY --from=builder /build/webhook /usr/local/bin/webhook

USER 65534:65534

ENTRYPOINT ["/usr/local/bin/webhook"]

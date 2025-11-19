FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git gcc musl-dev make

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the scanner
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w" \
    -o inkog-scanner \
    ./cmd/scanner

# Final stage
FROM alpine:3.18

# Install runtime dependencies
RUN apk add --no-cache ca-certificates git curl

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/inkog-scanner /usr/local/bin/

# Create non-root user
RUN addgroup -g 1000 scanner && \
    adduser -D -u 1000 -G scanner scanner

# Set permissions
RUN chmod +x /usr/local/bin/inkog-scanner

# Use non-root user
USER scanner

ENTRYPOINT ["inkog-scanner"]

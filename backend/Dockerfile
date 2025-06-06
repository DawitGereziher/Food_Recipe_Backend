# Stage 1 - Build the Go binary
FROM golang:1.23.2-bookworm as builder

# Set the working directory
WORKDIR /app

# Copy go.mod and go.sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the Go app statically
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o auth-server ./main.go

# Stage 2 - Lightweight runtime image
FROM gcr.io/distroless/static:nonroot

# Set working directory
WORKDIR /app

# Copy the built binary from the builder stage
COPY --from=builder /app/auth-server .

# Run as non-root user
USER nonroot:nonroot

# Start the application
ENTRYPOINT ["/app/auth-server"]

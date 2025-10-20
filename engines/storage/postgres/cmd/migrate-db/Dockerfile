FROM golang:1.23-alpine AS builder

WORKDIR /app

# Copy go modules files
COPY go.work go.work
COPY backend/go.mod backend/go.sum backend/
COPY core/go.mod core/go.sum core/
COPY engines/storage/postgres/go.mod engines/storage/postgres/go.sum engines/storage/postgres/
COPY shared/aws/go.mod shared/aws/go.sum shared/aws/
COPY shared/http/go.mod shared/http/go.sum shared/http/
COPY shared/subsystems/go.mod shared/subsystems/go.sum shared/subsystems/

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the migration tool
WORKDIR /app/engines/storage/postgres/cmd/migrate-db
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o /migrate-db .

# Final stage
FROM alpine:3.19

RUN apk --no-cache add ca-certificates

WORKDIR /root/

COPY --from=builder /migrate-db .

ENTRYPOINT ["./migrate-db"]

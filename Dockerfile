FROM golang:1.21-alpine AS builder

WORKDIR /app

RUN apk add --no-cache gcc musl-dev

COPY go.mod go.sum ./
RUN go mod download

COPY *.go ./
COPY LICENSE ./
COPY web ./web

RUN CGO_ENABLED=1 GOOS=linux go build -o traffic-monitor-enhanced .

FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /root/

COPY --from=builder /app/traffic-monitor-enhanced .

EXPOSE 8080

CMD ["./traffic-monitor-enhanced"]

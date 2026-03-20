FROM golang:1.24-alpine AS builder

WORKDIR /src
COPY go.mod ./
COPY main.go ./
RUN go build -trimpath -ldflags="-s -w" -o /out/supply-chain-demo .

FROM alpine:3.22

RUN addgroup -S app && adduser -S -G app app
WORKDIR /app
COPY --from=builder /out/supply-chain-demo /usr/local/bin/supply-chain-demo

EXPOSE 8080
USER app

ENTRYPOINT ["/usr/local/bin/supply-chain-demo"]

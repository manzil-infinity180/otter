FROM golang:1.24-alpine3.22 AS builder

WORKDIR /app

COPY . /app

RUN go build -o otter .

FROM scratch

WORKDIR /app
COPY --from=builder /app/otter /app

EXPOSE 7789

CMD ["/app/otter"]
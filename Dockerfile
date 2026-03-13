FROM aquasec/trivy:0.69.3 AS trivy
FROM ghcr.io/sigstore/cosign/cosign:v2.4.1 AS cosign

FROM golang:1.24-alpine3.22 AS builder

WORKDIR /app

COPY . /app

RUN go build -o otter .

FROM alpine:3.22

WORKDIR /app
RUN apk add --no-cache ca-certificates

COPY --from=builder /app/otter /usr/local/bin/otter
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=cosign /ko-app/cosign /usr/local/bin/cosign

EXPOSE 7789

CMD ["otter"]

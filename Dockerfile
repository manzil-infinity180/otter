FROM node:22-alpine3.22 AS frontend-builder

WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM aquasec/trivy:0.69.3 AS trivy
FROM ghcr.io/sigstore/cosign/cosign:v2.4.1 AS cosign

FROM golang:1.24-alpine3.22 AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . /app
RUN go build -o otter .

FROM alpine:3.22

WORKDIR /app
RUN apk add --no-cache ca-certificates
RUN addgroup -S otter && adduser -S -G otter otter && mkdir -p /app/data && chown -R otter:otter /app

COPY --from=builder /app/otter /usr/local/bin/otter
COPY --from=builder /app/db/migrations /app/db/migrations
COPY --from=frontend-builder /app/frontend/dist /app/frontend/dist
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=cosign /ko-app/cosign /usr/local/bin/cosign

EXPOSE 7789

USER otter

CMD ["otter"]

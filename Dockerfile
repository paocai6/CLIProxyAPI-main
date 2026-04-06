# Stage 1: Build WebUI
FROM node:22-alpine AS webui-builder

WORKDIR /webui

COPY webui/package.json webui/package-lock.json ./

RUN npm ci

COPY webui/ .

RUN npm run build

# Stage 2: Build Go binary
FROM golang:1.26-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

# Copy built webui into embedded static dir before Go build
COPY --from=webui-builder /webui/dist/index.html ./internal/managementasset/static/management.html

ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE=unknown

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X 'main.Version=${VERSION}' -X 'main.Commit=${COMMIT}' -X 'main.BuildDate=${BUILD_DATE}'" -o ./CLIProxyAPI ./cmd/server/

# Stage 3: Final image
FROM alpine:3.22.0

RUN apk add --no-cache tzdata

RUN mkdir /CLIProxyAPI

COPY --from=builder ./app/CLIProxyAPI /CLIProxyAPI/CLIProxyAPI

COPY config.example.yaml /CLIProxyAPI/config.example.yaml

# Copy built webui as static file
RUN mkdir -p /CLIProxyAPI/static
COPY --from=webui-builder /webui/dist/index.html /CLIProxyAPI/static/management.html

WORKDIR /CLIProxyAPI

EXPOSE 8317

ENV TZ=Asia/Shanghai

RUN cp /usr/share/zoneinfo/${TZ} /etc/localtime && echo "${TZ}" > /etc/timezone

CMD ["./CLIProxyAPI"]

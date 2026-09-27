# syntax=docker/dockerfile:1
FROM golang:1.24-alpine AS build
# 依赖 github.com/Helix2010/authorization-go-sdk 是私有仓库：用 `docker build --ssh default .` 把本机能读它的
# SSH 身份借给下载那一步（BuildKit 的 ssh 挂载，不进镜像层）。主机密钥是 GitHub 公布的 ed25519 那把
ENV GOPRIVATE=github.com/Helix2010/authorization-go-sdk
RUN apk add --no-cache git openssh-client \
 && install -m 700 -d /root/.ssh \
 && echo 'github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl' > /root/.ssh/known_hosts \
 && git config --global url."ssh://git@github.com/Helix2010/authorization-go-sdk".insteadOf "https://github.com/Helix2010/authorization-go-sdk"
WORKDIR /src
COPY go.mod go.sum ./
# replace 指向 ./signing：go mod download 之前这个目录就得在
COPY signing ./signing
RUN --mount=type=ssh go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/rn-server ./cmd/server

FROM alpine:3.22 AS runtime
RUN apk add --no-cache ca-certificates tzdata && addgroup -S app && adduser -S -G app app
WORKDIR /app
COPY --from=build /out/rn-server ./rn-server
COPY contracts ./contracts
USER app
EXPOSE 3000
CMD ["./rn-server"]

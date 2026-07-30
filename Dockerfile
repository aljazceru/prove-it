# syntax=docker/dockerfile:1
#
# prove-it — confidential attestation playground.
#
# Multi-stage build: compile a static Go binary, ship it on a pinned
# debian:bookworm-slim runtime. Follows the Enclava platform conventions used
# by templates/debian-ssh-ngrok-template: non-root UID/GID 10001, encrypted
# state under /state/app-data, config handoff under
# /state/app-data/.enclava/config, readiness on :8080/livez.

# Builder stage. Production should pin this digest from the toolchain release
# used by CI; left tag-pinned here so the example stays buildable standalone.
FROM golang:1.22-bookworm AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN go vet ./... \
 && go test ./... \
 && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/prove-it .

# Runtime stage, digest-pinned to match the debian-ssh-ngrok template.
FROM debian:bookworm-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 user \
    && useradd --uid 10001 --gid 10001 --home-dir /home/user --shell /usr/sbin/nologin user \
    && mkdir -p /state/app-data/.enclava/config /home/user \
    && chown -R 10001:10001 /state /home/user

COPY --from=build /out/prove-it /usr/local/bin/prove-it

ENV PROVE_IT_ADDR=:8080 \
    ENCLAVA_CONFIG_DIR=/state/app-data/.enclava/config \
    ENCLAVA_STATE_PATH=/state/app-data

USER 10001:10001
WORKDIR /
EXPOSE 8080

# No TTY needed; the binary reads config from the handoff dir and serves HTTP.
ENTRYPOINT ["/usr/local/bin/prove-it"]

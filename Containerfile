# Static musl build of rpm-server on a scratch base image.
# Build: podman build -t rpm-server -f Containerfile .
FROM docker.io/library/rust:1-slim AS build
WORKDIR /src
# ring's build script looks for a musl-prefixed gcc; the glibc gcc works for it.
ENV CC_x86_64_unknown_linux_musl=gcc \
  CC_aarch64_unknown_linux_musl=gcc
RUN rustup target add "$(uname -m)-unknown-linux-musl"

# Cache dependency builds separately from the sources.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src \
  && echo 'fn main() {}' > src/main.rs \
  && touch src/lib.rs \
  && cargo build --release --locked --target "$(uname -m)-unknown-linux-musl" \
  && rm -rf src

COPY src ./src
RUN touch src/main.rs src/lib.rs \
  && cargo build --release --locked --target "$(uname -m)-unknown-linux-musl" \
  && cp "target/$(uname -m)-unknown-linux-musl/release/rpm-server" /rpm-server

FROM scratch
COPY --from=build /rpm-server /rpm-server
ENV RPM_SERVER_DIR=/srv/rpms \
  RPM_SERVER_LISTEN=0.0.0.0:8080
EXPOSE 8080
USER 65532:65532
# Kept only in docker-format images: build with `podman build --format docker`.
# Healthchecks during the start period (initial scan of the folder) don't count.
HEALTHCHECK --interval=30s --timeout=10s --start-period=5m --retries=3 \
  CMD ["/rpm-server", "--healthcheck"]
ENTRYPOINT ["/rpm-server"]

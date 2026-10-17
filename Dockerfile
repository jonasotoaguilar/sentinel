# Sentinel — container image for pipeline users who do not want to install anything.
#
# Build with:  docker build -t sentinel .
# Run against a checkout:  docker run --rm -v "$PWD:/repo:ro" sentinel
#
# The default command scans the mounted repository in hermetic CI mode.
# ENTRYPOINT stays `sentinel` (exec form) and CMD holds only the default
# arguments, so any arguments passed to `docker run` replace the default
# scan instead of being swallowed: `docker run <image> cache path` and
# `docker run <image> scan --offline /other-mount` both work unchanged.
#
# Notes on the shape (each line is a property of the tool, not a preference):
# - Runtime carries git: discovery is Git-aware (`git ls-files` is the
#   tracked-file authority and scanning outside a repository exits 2), so an
#   image without git would turn every scan into a diagnostic.
# - Runtime carries ca-certificates: advisory lookups speak TLS (rustls),
#   and without a trust store every networked scan degrades to warnings.
# - The image is linux/amd64, built on the release runner; other platforms
#   use the per-target archives attached to the same Release.
# - The build stage pins the toolchain (1.91, the crate's rust-version) and
#   compiles with --locked, so the image binary is the exact dependency
#   tree the lockfile pins — the same tree the release archives use.

# --- build stage: compile the release binary, then throw the toolchain away.
FROM rust:1.91-slim-bookworm AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

# --- runtime stage: scanner binary plus the two things a scan needs (git,
# trust store). No toolchain, no build cache, no source tree.
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/sentinel /usr/local/bin/sentinel
RUN useradd --create-home --user-group --shell /usr/sbin/nologin sentinel
WORKDIR /repo
USER sentinel
ENTRYPOINT ["sentinel"]
CMD ["scan", "--ci", "/repo"]

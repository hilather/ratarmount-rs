# Build in the runtime distribution so host glibc does not leak into the image.
FROM rust:1.90-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev libarchive-dev libfuse3-dev cmake \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN CARGO_BUILD_JOBS=4 cargo build --locked --release -p ratarmount -p ratarmount-csi

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    fuse3 ca-certificates libssl3 liblzma5 libbz2-1.0 libzstd1 libarchive13 \
    && rm -rf /var/lib/apt/lists/* \
    && printf 'user_allow_other\n' > /etc/fuse.conf
COPY --from=build /src/target/release/ratarmount /src/target/release/ratarmount-csi /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/ratarmount-csi"]

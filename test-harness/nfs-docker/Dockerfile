# Privileged kernel-NFS client for ratarmount --nfs (v3 and v4.1).
# Host launcher bind-mounts the shipped binary + inside.sh.
# Not used by default CI (needs docker --privileged).
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# nfs-common → mount.nfs / mount.nfs4. libarchive13 + libfuse3-3 match
# the dynamically linked cargo binary on Ubuntu 24.04.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        nfs-common \
        rpcbind \
        libarchive13 \
        libfuse3-3 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
ENTRYPOINT ["/bin/bash", "/usr/local/bin/nfs-it-inside.sh"]

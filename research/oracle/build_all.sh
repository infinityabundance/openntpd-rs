#!/bin/sh
# Build all Docker oracle images
set -e
for df in Dockerfile.debian13 Dockerfile.ubuntu24 Dockerfile.rocky9 Dockerfile.freebsd14; do
    tag=$(echo $df | sed 's/Dockerfile\.//')
    echo "Building openntpd-oracle:$tag..."
    docker build -t openntpd-oracle:$tag -f $df .
done
echo "All images built."

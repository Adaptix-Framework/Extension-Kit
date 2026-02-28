FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    make \
    build-essential \
    python3 \
    gcc-mingw-w64-x86-64 \
    g++-mingw-w64-x86-64 \
    gcc-mingw-w64-i686 \
    g++-mingw-w64-i686 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

CMD ["make", "all"]
# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM rust:1.94-slim-trixie AS builder

ARG TARGETARCH
ARG BUILDPLATFORM
ARG APP_NAME=server

WORKDIR /app

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    gcc-aarch64-linux-gnu \
    g++-aarch64-linux-gnu \
    libc6-dev-arm64-cross \
    build-essential \
    git \
    make \
    cmake \
    perl \
    golang \
    ninja-build \
    autoconf \
 && rm -rf /var/lib/apt/lists/*

RUN case "${TARGETARCH}" in \
      "amd64") echo "x86_64-unknown-linux-gnu"  > /rust_target ;; \
      "arm64") echo "aarch64-unknown-linux-gnu" > /rust_target ;; \
      "aarch64") echo "aarch64-unknown-linux-gnu" > /rust_target ;; \
      *) echo "Unsupported arch: ${TARGETARCH}" && exit 1 ;; \
    esac

COPY . .

RUN RUST_TARGET="$(cat /rust_target)" && \
    rustup target add "${RUST_TARGET}" && \
    cargo install --locked --bin ${APP_NAME} --verbose --path . --target "${RUST_TARGET}" && \
    cp target/"${RUST_TARGET}"/release/"${APP_NAME}" /app-bin && \
    rm -rf src target/"${RUST_TARGET}"/release/*

FROM gcr.io/distroless/cc-debian13:nonroot AS runtime

ENV RUST_LOG=server=info

COPY --from=builder /app-bin /app/server

USER nonroot

ENTRYPOINT ["/app/server"]
CMD ["start"]

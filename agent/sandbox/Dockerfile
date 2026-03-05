# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM rust:1.93-slim-trixie AS builder

ARG TARGETARCH
ARG BUILDPLATFORM
ARG APP_NAME=agent

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

FROM debian:trixie-slim AS sandbox

ARG DEFAULT_USER=phire
ARG DEFAULT_PASSWORD=pass

ENV RUST_LOG=info

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    openssh-server \
    htop \
    btop \
    locales \
    curl \
    jq \
    sudo \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /var/run/sshd

# Generate UTF-8 locale so tools like btop have a UTF-8 environment
RUN sed -i 's/^# *en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen \
    && locale-gen \
    && update-locale LANG=en_US.UTF-8

ENV LANG=en_US.UTF-8 \
    LC_ALL=en_US.UTF-8

RUN useradd -m -s /bin/bash "${DEFAULT_USER}" \
    && echo "${DEFAULT_USER}:${DEFAULT_PASSWORD}" | chpasswd \
    && mkdir -p /home/"${DEFAULT_USER}"/.ssh \
    && chown -R "${DEFAULT_USER}:${DEFAULT_USER}" /home/"${DEFAULT_USER}"/.ssh

RUN echo "${DEFAULT_USER} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/${DEFAULT_USER} \
    && chmod 0440 /etc/sudoers.d/${DEFAULT_USER}

RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && sed -i 's@^#AuthorizedKeysFile.*@AuthorizedKeysFile     .ssh/authorized_keys@' /etc/ssh/sshd_config

COPY --from=builder /app-bin /usr/local/bin/phirepass

RUN printf '#!/bin/sh\nset -e\n/usr/bin/ssh-keygen -A\n/usr/sbin/sshd -D -e &\nexec /usr/local/bin/phirepass start\n' > /usr/local/bin/entrypoint.sh \
    && chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 22

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

# syntax=docker/dockerfile:1

############################
# Stage 1: download wfx-with-ui binary
############################
FROM debian:bookworm-slim AS downloader

ARG WFX_VERSION=0.5.0
ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    zstd \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "x86_64") && \
    mkdir -p /out && \
    curl -fsSL "https://github.com/siemens/wfx/releases/download/v${WFX_VERSION}/wfx-with-ui-${WFX_VERSION}-linux-${ARCH}.tar.zst" \
    | zstd -d | tar -xf - wfx && \
    mv wfx /out/wfx


############################
# Stage 2: runtime image
############################
FROM gcr.io/distroless/static-debian13:nonroot

COPY --from=downloader /out/wfx /usr/bin/wfx

EXPOSE 8080 8081

ENTRYPOINT ["wfx", "--mgmt-host=0.0.0.0"]
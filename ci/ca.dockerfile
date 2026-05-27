<<<<<<< HEAD
ARG BUILDER=golang:1.26.2-bookworm
FROM ${BUILDER} AS builder
=======
#################################################################################################
#                                                                                               #
# Use the custom go fork as a base image                                                        #
#                                                                                               #
#################################################################################################

FROM ghcr.io/lamassuiot/golang-pqc:latest

#################################################################################################
#                                                                                               #
# Install the application                                                                       #
#                                                                                               #
#################################################################################################

>>>>>>> 5d46ef96 (Updated images to use custom go fork. Replaced normal dockerfiles with their pq equivalents.)
WORKDIR /app
# Instruct BuildKit's Syft scanner to also generate an SBOM attestation for
# this intermediate stage (in addition to the default final-stage scan).
ARG BUILDKIT_SBOM_SCAN_STAGE=true

# go.work/go.work.sum rarely change — keep as an early cache layer.
COPY go.work go.work
COPY go.work.sum go.work.sum

COPY core core
COPY shared shared
COPY sdk sdk
COPY backend backend
COPY engines engines
COPY monolithic monolithic
COPY connectors connectors

RUN GONOSUMDB=github.com/lamassuiot/lamassuiot GOPROXY=direct go work vendor

# Build args are declared after vendoring so that a version-only change does
# not bust the vendor cache layer.
ARG SHA1VER= # set by build script
ARG VERSION= # set by build script

RUN GONOSUMDB=github.com/lamassuiot/lamassuiot GOPROXY=direct go work vendor

<<<<<<< HEAD
RUN now=$(TZ=GMT date +"%Y-%m-%dT%H:%M:%SZ") && \
    CGO_ENABLED=0 GOOS=linux \
    go build \
      -tags nopkcs11 \
      -ldflags "-w -s -X main.version=$VERSION -X main.sha1ver=$SHA1VER -X main.buildTime=$now" \
      -mod vendor \
      -o ca \
      backend/cmd/ca/main.go

# gcr.io/distroless/static-debian12:nonroot provides:
#   - a minimal (~2 MB) static-binary runtime with CA certificates included
#   - a pre-configured non-root user (UID/GID 65532) with no shell or package manager
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /app/ca /ca
CMD ["/ca"]
=======
ENV GOSUMDB=off
RUN now=$(TZ=GMT date +"%Y-%m-%dT%H:%M:%SZ")&& \ 
    go build -ldflags "-X main.version=$VERSION -X main.sha1ver=$SHA1VER -X main.buildTime=$now" -o ca backend/cmd/ca/main.go 

#################################################################################################
#                                                                                               #
# Configure the environment                                                                     #
#                                                                                               #
#################################################################################################

# Alpine and scartch dont work for this image due to non corss compileable HSM library
ARG DEBIAN_FRONTEND=noninteractive

# Dependencies for pkcs11-proxy and opensc for pkcs11-tool
RUN apt-get update && \
    apt-get --no-install-recommends install -y git-core libc6-dev gcc make cmake libssl-dev libseccomp-dev opensc ca-certificates  && \
    apt-get clean

RUN git clone https://github.com/SUNET/pkcs11-proxy && \
    cd pkcs11-proxy && \
    cmake . && make && make install

# Clean build artifacts
RUN rm -rf /pkcs11-proxy
# Clean compilation dependencies
RUN apt-get remove -y git-core libc6-dev gcc make cmake libssl-dev libseccomp-dev && \
    apt-get autoremove -y && \
    apt-get clean

ARG USERNAME=lamassu
ARG USER_UID=1000
ARG USER_GID=$USER_UID

RUN groupadd --gid "$USER_GID" "$USERNAME" \
    && useradd --uid "$USER_UID" --gid "$USER_GID" -m "$USERNAME" 

USER $USERNAME

CMD ["/app/ca"]
>>>>>>> 5d46ef96 (Updated images to use custom go fork. Replaced normal dockerfiles with their pq equivalents.)

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

ENV GOSUMDB=off
RUN now=$(TZ=GMT date +"%Y-%m-%dT%H:%M:%SZ")&& \
    go build -ldflags "-X main.version=$VERSION -X main.sha1ver=$SHA1VER -X main.buildTime=$now" -o device-manager backend/cmd/device-manager/main.go 

#################################################################################################
#                                                                                               #
# Configure the environment                                                                     #
#                                                                                               #
#################################################################################################

ARG USERNAME=lamassu
ARG USER_UID=1000
ARG USER_GID=$USER_UID

RUN groupadd --gid "$USER_GID" "$USERNAME" \
    && useradd --uid "$USER_UID" --gid "$USER_GID" -m "$USERNAME" 

USER $USERNAME

CMD ["/app/device-manager"]

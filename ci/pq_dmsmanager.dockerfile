FROM ubuntu:22.04

#################################################################################################
#                                                                                               #
# Install the Go fork                                                                           #
#                                                                                               #
#################################################################################################

RUN apt-get update -y && apt-get install -y software-properties-common git
RUN add-apt-repository ppa:longsleep/golang-backports
RUN apt-get update -y && apt-get install -y golang-go

WORKDIR /
RUN git clone https://github.com/lamassuiot/pqc-cloudflare-go.git

WORKDIR /pqc-cloudflare-go
RUN cd src && ./make.bash
ENV PATH "/pqc-cloudflare-go/bin:$PATH"

#################################################################################################
#                                                                                               #
# Install the application                                                                       #
#                                                                                               #
#################################################################################################

WORKDIR /app

COPY core core
COPY shared shared
COPY sdk sdk
COPY backend backend
COPY engines engines
COPY monolithic monolithic
COPY connectors connectors

COPY go.work go.work
COPY go.work.sum go.work.sum

ARG SHA1VER= # set by build script
ARG VERSION= # set by build script

RUN go work vendor

ENV GOSUMDB=off
RUN now=$(TZ=GMT date +"%Y-%m-%dT%H:%M:%SZ")&& \
    go build -ldflags "-X main.version=$VERSION -X main.sha1ver=$SHA1VER -X main.buildTime=$now" -o dms-manager backend/cmd/dms-manager/main.go 

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

CMD ["/app/dms-manager"]

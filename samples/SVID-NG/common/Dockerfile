# WL's common dependencies

# Stage 1 - Builder Img
# Define the building base image
FROM golang:alpine3.16
LABEL "type"="common"

# Set environmet variables
ENV GO111MODULE=on \
    CGO_ENABLED=1 \
    GOOS=linux \
    GOARCH=amd64 \
    GCCGO=gccgo \
    CGO_CFLAGS="-g -O2" \
    CGO_CXXFLAGS="-g -O2" \
    CGO_FFLAGS="-g -O2" \
    CGO_LDFLAGS="-g -O2" \
    CC="gcc"

# Create and move to working directory
WORKDIR /common-build

# Download dependencies
RUN apk upgrade --update-cache --available && \
    apk add openssl
RUN apk add git zip curl wget ca-certificates
RUN apk add xxd
RUN apk add sed
RUN apk add jq
RUN apk add openssl-dev
RUN apk add build-base
RUN apk add pkgconfig

COPY ./samples/SVID-NG/common .
RUN go mod download
# CMD ["./temp"]

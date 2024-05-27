# Stage 1 - Builder Image
# Defines the base image common on all other workloads
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

# Download dependencies
RUN apk upgrade --update-cache --available && \
    apk add openssl git zip curl wget \ 
    ca-certificates xxd sed jq \
    openssl-dev build-base pkgconfig
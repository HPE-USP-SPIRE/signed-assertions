# Stage 1 - Builder Img
# Define the building base image
FROM svid-ng_common AS builder

# Set environmet variables
# ENV GO111MODULE=on \
#     CGO_ENABLED=1 \
#     GOOS=linux \
#     GOARCH=amd64 \
#     GCCGO=gccgo \
#     CGO_CFLAGS="-g -O2" \
#     CGO_CXXFLAGS="-g -O2" \
#     CGO_FFLAGS="-g -O2" \
#     CGO_LDFLAGS="-g -O2" \
#     CC="gcc"

# Download dependencies
# RUN apk upgrade --update-cache --available && \
#     apk add openssl
# RUN apk add git zip curl wget ca-certificates
# RUN apk add xxd
# RUN apk add sed
# RUN apk add jq
# RUN apk add openssl-dev
# RUN apk add build-base
# RUN apk add pkgconfig

# Create and move to working directory
WORKDIR /build

# Copy files to Img
COPY ./samples/SVID-NG/Assertingwl-mTLS .
COPY ./samples/SVID-NG/api-libs /aux/api-libs
COPY ./poclib /aux/poclib

# Check if something changed in the files that affect the compilation of the Go program. If so, build a new program, and use the hash of those files as its name. 
RUN files_hash=$(find "." -type f -exec sha256sum {} \; | sed '/Dockerfile/d' | sed '/bin/d' | sed '/README/d' | LC_ALL=C sort -d | sha256sum | head -c 64); \
if test ! -f bin/$files_hash; \
  then rm /build/bin/*; \ 
  mv /aux/api-libs .; \
  mv /aux/poclib .; \
  go build -o /build/bin/main main.go; \
fi

# Stage 2 - Application Img
# Define the running base image 
FROM alpine:3.16 

LABEL "type"="assertingwl"

### Set working directory  
RUN mkdir /build
WORKDIR /build

### Copy in built application and other files
COPY --from=builder /build /build
# RUN chmod +x ./poclib/jwk2der.sh
RUN apk add --no-cache bash

# Export necessary port
EXPOSE 8443

# Command to run when starting the container
CMD ["/build/bin/main"]
# - or instead for debuging ... ENTRYPOINT ["tail", "-f", "/dev/null"]

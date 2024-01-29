# Stage 1 - Builder Img
# Define the building base image
FROM phase3_common AS builder

# Create and move to working directory
WORKDIR /build

# Copy files to Img
COPY ./samples/phase3/m-tier .
COPY ./samples/phase3/api-libs /aux/api-libs
COPY ./poclib /aux/poclib
COPY ./lsvid /aux/lsvid
COPY ./go-spiffe /aux/go-spiffe

# Check if something changed in the files that affect the compilation of the Go program. If so, build a new program, and use the hash of those files as its name. In any case, create a bash script to execute the binary (fix name for CMD in the end of the dockerfile).
RUN files_hash=$(find "." -type f -exec sha256sum {} \; | sed '/Dockerfile/d' | sed '/bin/d' | sed '/README/d' | LC_ALL=C sort -d | sha256sum | head -c 64); \
if test ! -f bin/$files_hash; \
  then rm -f /build/bin/*; \ 
  mv /aux/api-libs .; \
  mv /aux/poclib .; \
  mv /aux/lsvid .; \
  mv /aux/go-spiffe .; \
  go mod download; \
  go build -o /build/bin/$files_hash main.go; \
fi; \
echo "./bin/$files_hash" > main.sh; \
chmod +x main.sh

# Stage 2 - Application Img
# Define the running base image 
FROM alpine:3.16 

LABEL "type"="middletier"

### Set working directory  
RUN mkdir /build
WORKDIR /build

### Copy in built application and other files
COPY --from=builder /build /build
# RUN chmod +x ./poclib/jwk2der.sh
RUN apk add --no-cache bash

# Export necessary port
EXPOSE 8445

# Command to run when starting the container
CMD ["bash","/build/main.sh"]

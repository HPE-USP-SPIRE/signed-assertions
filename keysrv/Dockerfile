# Stage 1 - Builder Img
# Define the building base image
FROM golang:alpine AS builder

# Set environmet variables
ENV GO111MODULE=on \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

LABEL "type"="MockMeta"

# Create and move to working directory
RUN mkdir /build
WORKDIR /build

# Copy in files to Img
COPY . .

# Download dependencies
RUN go mod download
RUN go build -o main .

# Stage 2 - Application Img
# Define the running base image 
FROM alpine 

### Set working directory  
RUN mkdir /build
WORKDIR /build

### Copy in built application and other files
COPY --from=builder /build /build

# Export necessary port
EXPOSE 8888

# Command to run when starting the container
CMD ["/build/main"]
# - or instead for debuging ... ENTRYPOINT ["tail", "-f", "/dev/null"]
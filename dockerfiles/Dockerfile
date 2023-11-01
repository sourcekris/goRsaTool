# Build goRsaTool binary from source on ubuntu base.
FROM ubuntu

# Add dependencies.
RUN apt update && apt install -y git \
    golang \
    make \
    libflint-dev \
    libecm-dev

# Build the tool
RUN go install github.com/sourcekris/goRsaTool@latest
RUN cp /root/go/bin/goRsaTool /usr/local/bin

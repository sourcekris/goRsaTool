# Build a statically linked goRsaTool binary from source for linux-amd64
FROM golang:alpine
LABEL os=linux
LABEL arch=amd64
ENV GOOS=linux
ENV GOARCH=amd64
ENV CGO_ENABLED=1
ENV CC=gcc
ENV FLINT_VER=2.8.0
ENV PATH="/go/bin/${GOOS}_${GOARCH}:${PATH}"

# Add dependencies.
RUN apk add gcc \
    libc-dev \
    gmp-dev \
    mpfr-dev \
    pkgconfig \
    make \
    git \
    wget \
    autoconf \
    automake \
    libtool

# alpine flint-dev package is not complete so compile from source.
RUN cd /root && wget https://www.flintlib.org/flint-${FLINT_VER}.tar.gz && \
    tar xvf flint-${FLINT_VER}.tar.gz && \
    cd flint-${FLINT_VER} && ./configure --disable-pthread --prefix=/usr && \
    make && make install

RUN cd /root && git clone https://gitlab.inria.fr/zimmerma/ecm.git && cd ecm && \
    libtoolize && autoreconf -i && ./configure --prefix=/usr && \
    make && make install

# get the tool & dependency source using the pre-modules method.
RUN GO111MODULE=off go get github.com/sourcekris/goRsaTool

# statically compile it
ENV CGO_LDFLAGS="/usr/lib/libmpfr.a /usr/lib/libecm.a /usr/lib/libm.a /usr/lib/libgmp.a"
RUN cd /go/src/github.com/sourcekris/goRsaTool && go build -ldflags="-extldflags=-static" && \
    cp goRsaTool /go/bin
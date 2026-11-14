build:
	go build

run:
	go run rsatool.go

release-darwin-arm64:
	CGO_LDFLAGS="/opt/homebrew/lib/libmpfr.a /opt/homebrew/lib/libgmp.a /opt/homebrew/lib/libflint.a /usr/local/lib/libecm.a" go build

release-linux-amd64:
	CGO_LDFLAGS="/usr/lib/libmpfr.a /usr/lib/libecm.a /usr/lib/libm.a /usr/lib/libgmp.a" go build -ldflags="-extldflags=-static"

release-windows-amd64:
	CGO_CPPFLAGS="-IC:/msys64/ucrt64/include" CGO_LDFLAGS="-LC:/msys64/ucrt64/lib" go build -o goRsaTool.exe rsatool.go

clean:
	go clean -i ./...

test:
	go test -v ./...

install:
	go build -o /usr/local/bin/goRsaTool rsatool.go

all: install
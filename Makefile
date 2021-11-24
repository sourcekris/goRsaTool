build:
	go build

run:
	go run rsatool.go

clean:
	go clean -i ./...

test:
	go test -v ./...

install:
	go build -o /usr/local/bin/goRsaTool rsatool.go

all: install
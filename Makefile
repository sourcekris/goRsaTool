build:
	go build

run:
	go run rsatool.go

clean:
	go clean -i ./...

test:
	go test -v ./...

install:
	go install rsatool.go

all: build
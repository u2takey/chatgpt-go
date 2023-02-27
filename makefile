.PHONY: test build run

test:
	go test ./...

build:
	mkdir -p ./output
	cd cmd && go build -o ../output/chat-service . && cd -

build-linux:
	cd cmd && GOOS=linux GOARCH=amd64 go build -o ../output/chat-service . && cd -

docker: build-linux
	docker build -t chat-service .

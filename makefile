.PHONY: test build run

test:
	go test ./...

build:
	mkdir -p ./output
	cd chat-service && go build -o ../output/chat-service . && cd -

build-linux:
	cd chat-service && GOOS=linux GOARCH=amd64 go build -o ../output/chat-service . && cd -

docker: build-linux
	docker build -t chat-service .

run-docker: docker
	docker run -p 8088:8088 chat-service
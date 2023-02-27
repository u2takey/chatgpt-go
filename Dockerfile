FROM alpine
RUN apk update && apk add ca-certificates
ADD ./output/chat-service /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/chat-service"]
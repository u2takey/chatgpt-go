# chatgpt-go
golang version for chatgpt api.

Just a golang port for [acheong08/ChatGPT(v1-standard-chatgpt)](https://github.com/acheong08/ChatGPT)

Refer to [test](./chatgpt_test.go) for usage.


## chatgpt-service 

serve chatgpt-api as http service

```sh
>> make docker 
>> docker run -p 8088:8088 chat-service

>> curl localhost:8088/bind -d '{"user_id": "test", "access_token": "xxx"}'
{"code":200,"message":""}%                                                                                                                                                                                                 

>>> curl localhost:8088/ask -d '{"user_id": "test", "prompt": "什么是快乐星球"}'
{"code":0,"message":"","data":{"message":"xxxxx","conversation_id":"6309e31b-ab58-42ae-8af5-f9cda3881bf8","parent_id":"ab0ff560-2140-4333-975d-8b147728cc0f","model":""}}%
```
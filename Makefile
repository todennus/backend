start-rest:
	go run ./cmd/main.go rest

start-grpc:
	go run ./cmd/main.go grpc

start-swagger:
	go run ./cmd/main.go swagger

docker-build:
	docker build -t todennus/backend -f ./build/package/Dockerfile .

swagger-gen:
	swag init --dir ./adapter/rest/ -g app.go

proto-gen:
	rm -rf ./adapter/grpc/gen/* && \
	protoc --go_out=./adapter/grpc/gen --go_opt=paths=source_relative \
    	--go-grpc_out=./adapter/grpc/gen --go-grpc_opt=paths=source_relative \
    	-I=../proto/ -I=../proto/dto/  -I=../proto/dto/resource/ \
		../proto/dto/resource/*.proto ../proto/dto/*.proto ../proto/*.proto

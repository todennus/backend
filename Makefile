start-rest:
	go run ./cmd/main.go rest

start-grpc:
	go run ./cmd/main.go grpc

docker-build:
	docker build -t todennus/oauth2-service -f ./build/package/Dockerfile .

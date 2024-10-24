package grpc

import (
	service "github.com/todennus/backend/adapter/grpc/gen"
	"github.com/todennus/backend/adapter/grpc/interceptor"
	"github.com/todennus/backend/wiring"
	"github.com/todennus/config"
	"google.golang.org/grpc"
)

func App(config *config.Config, infras *wiring.Infras, usecases *wiring.Usecases) *grpc.Server {
	s := grpc.NewServer(
		grpc.UnaryInterceptor(interceptor.UnaryInterceptor(config, infras)),
	)

	service.RegisterUserServer(s, NewUserServer(usecases.UserUsecase))

	return s
}

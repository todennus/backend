package grpc

import (
	"context"

	"github.com/todennus/oauth2-service/domain"
	"github.com/todennus/proto/gen/service"
	"github.com/todennus/proto/gen/service/dto"
	"github.com/todennus/shared/authentication"
	"github.com/todennus/shared/errordef"
	"github.com/xybor-x/snowflake"
	"google.golang.org/grpc"
)

type UserRepository struct {
	auth   *authentication.GrpcAuthorization
	client service.UserClient
}

func NewUserRepository(conn *grpc.ClientConn, auth *authentication.GrpcAuthorization) *UserRepository {
	return &UserRepository{
		client: service.NewUserClient(conn),
		auth:   auth,
	}
}

func (repo *UserRepository) GetByID(ctx context.Context, userID snowflake.ID) (*domain.User, error) {
	req := &dto.UserGetByIDRequest{Id: userID.Int64()}
	resp, err := repo.client.GetByID(repo.auth.Context(ctx), req)
	if err != nil {
		return nil, errordef.ConvertGRPCError(err)
	}

	return NewUser(resp.User), nil
}

func (repo *UserRepository) Validate(ctx context.Context, username string, password string) (*domain.User, error) {
	req := &dto.UserValidateRequest{Username: username, Password: password}
	resp, err := repo.client.Validate(repo.auth.Context(ctx), req)
	if err != nil {
		return nil, errordef.ConvertGRPCError(err)
	}

	return NewUser(resp.User), nil
}

package grpc

import (
	"context"

	"github.com/todennus/oauth2-service/domain"
	"github.com/todennus/proto/gen/service"
	"github.com/todennus/proto/gen/service/dto"
	"github.com/todennus/shared/errordef"
	"github.com/xybor-x/snowflake"
	"google.golang.org/grpc"
)

type UserRepository struct {
	client service.UserClient
}

func NewUserRepository(conn *grpc.ClientConn) *UserRepository {
	return &UserRepository{
		client: service.NewUserClient(conn),
	}
}

func (repo *UserRepository) GetByID(ctx context.Context, userID snowflake.ID) (*domain.User, error) {
	resp, err := repo.client.GetByID(ctx, &dto.UserGetByIDRequest{Id: userID.Int64()})
	if err != nil {
		return nil, errordef.ConvertGRPCError(err)
	}

	return NewUser(resp.User), nil
}

func (repo *UserRepository) Validate(ctx context.Context, username string, password string) (*domain.User, error) {
	resp, err := repo.client.Validate(ctx, &dto.UserValidateRequest{
		Username: username,
		Password: password,
	})

	if err != nil {
		return nil, errordef.ConvertGRPCError(err)
	}

	return NewUser(resp.User), nil
}

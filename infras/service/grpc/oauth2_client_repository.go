package grpc

import (
	"context"

	"github.com/todennus/oauth2-service/domain"
	"github.com/todennus/proto/gen/service"
	"github.com/todennus/proto/gen/service/dto"
	"github.com/todennus/shared/authentication"
	"github.com/todennus/shared/enumdef"
	"github.com/todennus/shared/errordef"
	"github.com/xybor-x/snowflake"
	"google.golang.org/grpc"
)

type OAuth2ClientRepository struct {
	auth   *authentication.GrpcAuthorization
	client service.OAuth2ClientClient
}

func NewOAuth2ClientRepository(conn *grpc.ClientConn, auth *authentication.GrpcAuthorization) *OAuth2ClientRepository {
	return &OAuth2ClientRepository{
		client: service.NewOAuth2ClientClient(conn),
		auth:   auth,
	}
}

func (repo *OAuth2ClientRepository) GetByID(ctx context.Context, clientID snowflake.ID) (*domain.OAuth2Client, error) {
	req := &dto.OAuth2ClientGetByIDRequest{ClientId: clientID.Int64()}
	resp, err := repo.client.GetByID(repo.auth.Context(ctx), req)
	if err != nil {
		return nil, errordef.ConvertGRPCError(err)
	}

	return NewOAuth2Client(resp.Client), nil
}

func (repo *OAuth2ClientRepository) Validate(
	ctx context.Context,
	clientID snowflake.ID,
	clientSecret string,
	requirement enumdef.OAuth2ClientConfidentialRequirement,
) (*domain.OAuth2Client, error) {
	req := &dto.OAuth2ClientValidateRequest{
		ClientId:     clientID.Int64(),
		ClientSecret: clientSecret,
		Requirement:  enumdef.OAuth2ClientConfidentialRequirementTypeToGRPC(requirement),
	}
	resp, err := repo.client.Validate(repo.auth.Context(ctx), req)
	if err != nil {
		return nil, errordef.ConvertGRPCError(err)
	}

	return NewOAuth2Client(resp.Client), nil
}

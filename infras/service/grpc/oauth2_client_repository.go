package grpc

import (
	"context"

	"github.com/todennus/oauth2-service/domain"
	"github.com/todennus/proto/gen/service"
	"github.com/todennus/proto/gen/service/dto"
	"github.com/todennus/shared/enumdef"
	"github.com/todennus/shared/errordef"
	"github.com/todennus/x/scope"
	"github.com/xybor-x/snowflake"
	"google.golang.org/grpc"
)

type OAuth2ClientRepository struct {
	client service.OAuth2ClientClient
}

func NewOAuth2ClientRepository(conn *grpc.ClientConn) *OAuth2ClientRepository {
	return &OAuth2ClientRepository{
		client: service.NewOAuth2ClientClient(conn),
	}
}

func (repo *OAuth2ClientRepository) GetByID(ctx context.Context, clientID snowflake.ID) (*domain.OAuth2Client, error) {
	resp, err := repo.client.GetByID(ctx, &dto.OAuth2ClientGetByIDRequest{ClientId: clientID.Int64()})
	if err != nil {
		return nil, errordef.ConvertGRPCError(err)
	}

	return NewOAuth2Client(resp.Client), nil
}

func (repo *OAuth2ClientRepository) Validate(
	ctx context.Context,
	clientID snowflake.ID,
	clientSecret string,
	requirement enumdef.ConfidentialRequirementType,
	requestedScope scope.Scopes,
) error {
	_, err := repo.client.Validate(ctx, &dto.OAuth2ClientValidateRequest{
		ClientId:       clientID.Int64(),
		ClientSecret:   clientSecret,
		Requirement:    enumdef.ConfidentialRequirementTypeToGRPC(requirement),
		RequestedScope: requestedScope.String(),
	})

	if err != nil {
		return errordef.ConvertGRPCError(err)
	}

	return nil
}

package grpc

import (
	"context"

	"github.com/todennus/oauth2-service/domain"
	"github.com/todennus/proto/gen/service"
	"github.com/todennus/proto/gen/service/dto"
	"github.com/todennus/shared/enumdef"
	"github.com/todennus/shared/errordef"
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

func (repo *OAuth2ClientRepository) GetByID(ctx context.Context, clientID int64) (*domain.OAuth2Client, error) {
	resp, err := repo.client.GetByID(ctx, &dto.OAuth2ClientGetByIDRequest{ClientId: clientID})
	if err != nil {
		return nil, errordef.ConvertGRPCError(err)
	}

	return NewOAuth2Client(resp.Client), nil
}

func (repo *OAuth2ClientRepository) Validate(
	ctx context.Context,
	clientID int64,
	clientSecret string,
	requirement enumdef.ConfidentialRequirementType,
	requestedScope string,
) error {
	_, err := repo.client.Validate(ctx, &dto.OAuth2ClientValidateRequest{
		ClientId:       clientID,
		ClientSecret:   clientSecret,
		Requirement:    enumdef.ConfidentialRequirementTypeToGRPC(requirement),
		RequestedScope: requestedScope,
	})

	if err != nil {
		return errordef.ConvertGRPCError(err)
	}

	return nil
}

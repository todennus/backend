package resource

import (
	"context"

	"github.com/todennus/oauth2-service/domain"
	"github.com/todennus/shared/scopedef"
	"github.com/xybor-x/snowflake"
)

type OAuth2Client struct {
	OwnerID      snowflake.ID
	ClientID     snowflake.ID
	Name         string
	AllowedScope string
}

func NewOAuth2Client(ctx context.Context, client *domain.OAuth2Client) *OAuth2Client {
	usecaseClient := &OAuth2Client{
		ClientID:     client.ID,
		OwnerID:      client.OwnerUserID,
		Name:         client.Name,
		AllowedScope: client.AllowedScope.String(),
	}

	Filter(ctx, &usecaseClient.OwnerID).WhenRequestUserNot(client.OwnerUserID)
	Filter(ctx, &usecaseClient.AllowedScope).
		WhenRequestUserNot(client.OwnerUserID).
		WhenNotContainsScope(scopedef.Engine.New(scopedef.Actions.Read, scopedef.Resources.Client.AllowedScope))

	return usecaseClient
}

func NewOAuth2ClientWithoutFilter(client *domain.OAuth2Client) *OAuth2Client {
	usecaseClient := &OAuth2Client{
		ClientID:     client.ID,
		OwnerID:      client.OwnerUserID,
		Name:         client.Name,
		AllowedScope: client.AllowedScope.String(),
	}

	return usecaseClient
}

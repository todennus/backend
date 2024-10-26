package resource

import (
	"github.com/todennus/oauth2-service/domain"
	"github.com/xybor-x/snowflake"
)

type OAuth2Client struct {
	ClientID snowflake.ID
	Name     string
}

func NewOAuth2ClientWithoutFilter(client *domain.OAuth2Client) *OAuth2Client {
	return &OAuth2Client{
		ClientID: client.ID,
		Name:     client.Name,
	}
}

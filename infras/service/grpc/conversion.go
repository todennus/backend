package grpc

import (
	"github.com/todennus/oauth2-service/domain"
	"github.com/todennus/proto/gen/service/dto/resource"
	"github.com/todennus/shared/enumdef"
	"github.com/todennus/shared/scopedef"
	"github.com/todennus/x/enum"
	"github.com/xybor-x/snowflake"
)

func NewUser(user *resource.User) *domain.User {
	return &domain.User{
		ID:          snowflake.ID(user.Id),
		Username:    user.Username,
		DisplayName: user.DisplayName,
		Role:        enum.FromStr[enumdef.UserRole](user.Role),
	}
}

func NewOAuth2Client(client *resource.OAuth2Client) *domain.OAuth2Client {
	return &domain.OAuth2Client{
		ID:           snowflake.ID(client.Id),
		Name:         client.Name,
		AllowedScope: scopedef.Engine.ParseScopes(client.AllowedScope),
	}
}

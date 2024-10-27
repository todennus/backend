package wiring

import (
	"context"
	"time"

	"github.com/todennus/oauth2-service/domain"
	"github.com/todennus/oauth2-service/usecase/abstraction"
	"github.com/todennus/shared/config"
)

type Domains struct {
	abstraction.OAuth2FlowDomain
	abstraction.OAuth2ConsentDomain
	abstraction.OAuth2SessionDomain
	abstraction.OAuth2TokenDomain
}

func InitializeDomains(ctx context.Context, config *config.Config) (*Domains, error) {
	domains := &Domains{}

	domains.OAuth2FlowDomain = domain.NewOAuth2FlowDomain(
		time.Duration(config.Variable.OAuth2.AuthorizationCodeFlowExpiration) * time.Second)

	domains.OAuth2ConsentDomain = domain.NewOAuth2ConsentDomain(
		time.Duration(config.Variable.OAuth2.ConsentSessionExpiration)*time.Second,
		time.Duration(config.Variable.OAuth2.ConsentExpiration)*time.Second,
	)

	domains.OAuth2SessionDomain = domain.NewOAuth2SessionDomain(
		time.Duration(config.Variable.OAuth2.AuthenticationCallbackExpiration)*time.Second,
		time.Duration(config.Variable.OAuth2.SessionUpdateExpiration)*time.Second,
		time.Duration(config.Variable.Session.Expiration)*time.Second,
	)

	domains.OAuth2TokenDomain = domain.NewOAuth2TokenDomain(
		config.SnowflakeNode,
		config.Variable.OAuth2.TokenIssuer,
		time.Duration(config.Variable.OAuth2.AccessTokenExpiration)*time.Second,
		time.Duration(config.Variable.OAuth2.RefreshTokenExpiration)*time.Second,
		time.Duration(config.Variable.OAuth2.IDTokenExpiration)*time.Second,
	)

	return domains, nil
}

package grpc

import (
	"context"
	"fmt"
	"time"

	"github.com/todennus/oauth2-service/domain"
	"github.com/todennus/oauth2-service/usecase/abstraction"
	"github.com/todennus/oauth2-service/usecase/dto"
	"github.com/todennus/x/scope"
	"github.com/todennus/x/token"
	"github.com/xybor-x/snowflake"
	"golang.org/x/oauth2"
)

var _ oauth2.TokenSource = (*selfAuthTokenSource)(nil)

type selfAuthTokenSource struct {
	ctx         context.Context
	client      *domain.OAuth2Client
	scope       scope.Scopes
	tokenEngine token.Engine
	tokenDomain abstraction.OAuth2TokenDomain
}

func (s *selfAuthTokenSource) Token() (*oauth2.Token, error) {
	accessToken := s.tokenDomain.NewClientAccessToken("", s.scope, s.client)
	accessTokenString, err := s.tokenEngine.Generate(s.ctx, dto.OAuth2AccessTokenFromDomain(accessToken))
	if err != nil {
		return nil, fmt.Errorf("failed to self auth: %w", err)
	}

	return &oauth2.Token{
		AccessToken: accessTokenString,
		TokenType:   s.tokenEngine.Type(),
		Expiry:      time.Unix(int64(accessToken.Metadata.ExpiresAt), 0),
	}, nil
}

func NewSelfAuthTokenSource(
	ctx context.Context,
	clientID snowflake.ID,
	scope scope.Scopes,
	tokenEngine token.Engine,
	tokenDomain abstraction.OAuth2TokenDomain,
) *selfAuthTokenSource {
	return &selfAuthTokenSource{
		ctx:         ctx,
		client:      &domain.OAuth2Client{ID: clientID, Name: "Self Auth Client", IsAdmin: true},
		scope:       scope,
		tokenEngine: tokenEngine,
		tokenDomain: tokenDomain,
	}
}

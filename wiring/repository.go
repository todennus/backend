package wiring

import (
	"context"
	"fmt"
	"strings"

	"github.com/todennus/oauth2-service/infras/database/composite"
	"github.com/todennus/oauth2-service/infras/database/gorm"
	"github.com/todennus/oauth2-service/infras/database/model"
	"github.com/todennus/oauth2-service/infras/database/redis"
	"github.com/todennus/oauth2-service/infras/service/grpc"
	"github.com/todennus/oauth2-service/usecase/abstraction"
	"github.com/todennus/shared/authentication"
	"github.com/todennus/shared/config"
	"github.com/todennus/shared/scopedef"
	"github.com/todennus/x/session"
	"github.com/todennus/x/xcrypto"
	"github.com/xybor-x/snowflake"
	"golang.org/x/oauth2"
)

type Repositories struct {
	abstraction.UserRepository
	abstraction.OAuth2RefreshTokenRepository
	abstraction.OAuth2ClientRepository
	abstraction.SessionRepository
	abstraction.OAuth2AuthorizationCodeRepository
	abstraction.OAuth2ConsentRepository
}

func InitializeRepositories(
	ctx context.Context,
	config *config.Config,
	infras *Infras,
	domains *Domains,
) (*Repositories, error) {
	r := &Repositories{}

	clientID, err := snowflake.ParseString(infras.AuthConfig.ClientID)
	if err != nil {
		return nil, fmt.Errorf("invalid client id: %w", err)
	}
	scopes := scopedef.Engine.ParseDefinedScopes(strings.Join(infras.AuthConfig.Scopes, " "))
	tokenSource := func(ctx context.Context) oauth2.TokenSource {
		return grpc.NewSelfAuthTokenSource(ctx, clientID, scopes, config.TokenEngine, domains.OAuth2TokenDomain)
	}

	r.UserRepository = grpc.NewUserRepository(
		infras.UsergRPCConn,
		authentication.NewGrpcAuthorization(tokenSource),
	)

	r.OAuth2ClientRepository = grpc.NewOAuth2ClientRepository(
		infras.OAuth2ClientgRPCConn,
		authentication.NewGrpcAuthorization(tokenSource),
	)

	r.OAuth2RefreshTokenRepository = gorm.NewOAuth2RefreshTokenRepository(infras.GormPostgres)

	r.SessionRepository = composite.NewSessionRepository(
		session.NewCookieStore[model.SessionModel](
			[]byte(config.Secret.Session.AuthenticationKey),
			xcrypto.GenerateAESKeyFromPassword(config.Secret.Session.EncryptionKey, 32),
		))
	r.OAuth2AuthorizationCodeRepository = redis.NewOAuth2AuthorizationCodeRepository(infras.Redis)
	r.OAuth2ConsentRepository = composite.NewOAuth2ConsentRepository(infras.GormPostgres, infras.Redis)

	return r, nil
}

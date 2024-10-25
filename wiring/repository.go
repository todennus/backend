package wiring

import (
	"context"

	"github.com/todennus/oauth2-service/infras/database/composite"
	"github.com/todennus/oauth2-service/infras/database/gorm"
	"github.com/todennus/oauth2-service/infras/database/model"
	"github.com/todennus/oauth2-service/infras/database/redis"
	"github.com/todennus/oauth2-service/infras/service/grpc"
	"github.com/todennus/oauth2-service/usecase/abstraction"
	"github.com/todennus/shared/config"
	"github.com/todennus/x/session"
	"github.com/todennus/x/xcrypto"
)

type Repositories struct {
	abstraction.UserRepository
	abstraction.RefreshTokenRepository
	abstraction.OAuth2ClientRepository
	abstraction.SessionRepository
	abstraction.OAuth2AuthorizationCodeRepository
	abstraction.OAuth2ConsentRepository
}

func InitializeRepositories(ctx context.Context, config *config.Config, infras *Infras) (*Repositories, error) {
	r := &Repositories{}

	r.UserRepository = grpc.NewUserRepository(infras.UsergRPCConn)
	r.RefreshTokenRepository = gorm.NewRefreshTokenRepository(infras.GormPostgres)
	r.OAuth2ClientRepository = gorm.NewOAuth2ClientRepository(infras.GormPostgres)
	r.SessionRepository = gorm.NewSessionRepository(
		session.NewCookieStore[model.SessionModel](
			[]byte(config.Secret.Session.AuthenticationKey),
			xcrypto.GenerateAESKeyFromPassword(config.Secret.Session.EncryptionKey, 32),
		))
	r.OAuth2AuthorizationCodeRepository = redis.NewOAuth2AuthorizationCodeRepository(infras.Redis)
	r.OAuth2ConsentRepository = composite.NewOAuth2ConsentRepository(infras.GormPostgres, infras.Redis)

	return r, nil
}

package wiring

import (
	"context"

	"github.com/todennus/backend/infras/database/composite"
	"github.com/todennus/backend/infras/database/gorm"
	"github.com/todennus/backend/infras/database/model"
	"github.com/todennus/backend/infras/database/redis"
	"github.com/todennus/backend/usecase/abstraction"
	"github.com/todennus/config"
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

func InitializeRepositories(ctx context.Context, config *config.Config, db *Databases) (*Repositories, error) {
	r := &Repositories{}

	r.UserRepository = gorm.NewUserRepository(db.GormPostgres)
	r.RefreshTokenRepository = gorm.NewRefreshTokenRepository(db.GormPostgres)
	r.OAuth2ClientRepository = gorm.NewOAuth2ClientRepository(db.GormPostgres)
	r.SessionRepository = gorm.NewSessionRepository(
		session.NewCookieStore[model.SessionModel](
			[]byte(config.Secret.Session.AuthenticationKey),
			xcrypto.GenerateAESKeyFromPassword(config.Secret.Session.EncryptionKey, 32),
		))
	r.OAuth2AuthorizationCodeRepository = redis.NewOAuth2AuthorizationCodeRepository(db.Redis)
	r.OAuth2ConsentRepository = composite.NewOAuth2ConsentRepository(db.GormPostgres, db.Redis)

	return r, nil
}

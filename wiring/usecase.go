package wiring

import (
	"context"
	"time"

	"github.com/todennus/oauth2-service/adapter/abstraction"
	"github.com/todennus/oauth2-service/usecase"
	"github.com/todennus/shared/config"
	"github.com/todennus/x/lock"
)

type Usecases struct {
	abstraction.OAuth2Usecase
	abstraction.OAuth2ClientUsecase
}

func InitializeUsecases(
	ctx context.Context,
	config *config.Config,
	infras *Infras,
	domains *Domains,
	repositories *Repositories,
) (*Usecases, error) {
	uc := &Usecases{}

	uc.OAuth2Usecase = usecase.NewOAuth2Usecase(
		config.TokenEngine,
		config.Variable.OAuth2.IdPLoginURL,
		config.Secret.OAuth2.IdPSecret,
		domains.OAuth2FlowDomain,
		domains.OAuth2ClientDomain,
		domains.OAuth2ConsentDomain,
		repositories.UserRepository,
		repositories.RefreshTokenRepository,
		repositories.OAuth2ClientRepository,
		repositories.SessionRepository,
		repositories.OAuth2AuthorizationCodeRepository,
		repositories.OAuth2ConsentRepository,
	)

	uc.OAuth2ClientUsecase = usecase.NewOAuth2ClientUsecase(
		lock.NewRedisLock(infras.Redis, "client-lock", 10*time.Second),
		domains.OAuth2ClientDomain,
		repositories.UserRepository,
		repositories.OAuth2ClientRepository,
	)

	return uc, nil
}

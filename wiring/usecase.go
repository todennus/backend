package wiring

import (
	"context"

	"github.com/todennus/oauth2-service/adapter/abstraction"
	"github.com/todennus/oauth2-service/usecase"
	"github.com/todennus/shared/config"
)

type Usecases struct {
	abstraction.OAuth2FlowUsecase
	abstraction.OAuth2AuthenticationUsecase
	abstraction.OAuth2ConsentUsecase
}

func InitializeUsecases(
	ctx context.Context,
	config *config.Config,
	infras *Infras,
	domains *Domains,
	repositories *Repositories,
) (*Usecases, error) {
	uc := &Usecases{}

	uc.OAuth2FlowUsecase = usecase.NewOAuth2FlowUsecase(
		config.TokenEngine,
		config.Variable.OAuth2.IdPLoginURL,
		domains.OAuth2FlowDomain,
		domains.OAuth2ConsentDomain,
		domains.OAuth2TokenDomain,
		domains.OAuth2SessionDomain,
		repositories.UserRepository,
		repositories.OAuth2RefreshTokenRepository,
		repositories.OAuth2ClientRepository,
		repositories.SessionRepository,
		repositories.OAuth2AuthorizationCodeRepository,
		repositories.OAuth2ConsentRepository,
	)

	uc.OAuth2AuthenticationUsecase = usecase.NewOAuth2AuthenticationUsecase(
		config.Secret.OAuth2.IdPSecret,
		domains.OAuth2SessionDomain,
		repositories.UserRepository,
		repositories.SessionRepository,
		repositories.OAuth2AuthorizationCodeRepository,
	)

	uc.OAuth2ConsentUsecase = usecase.NewOAuth2ConsentUsecase(
		domains.OAuth2ConsentDomain,
		domains.OAuth2SessionDomain,
		repositories.OAuth2ClientRepository,
		repositories.SessionRepository,
		repositories.OAuth2AuthorizationCodeRepository,
		repositories.OAuth2ConsentRepository,
	)

	return uc, nil
}

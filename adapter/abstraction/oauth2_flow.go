package abstraction

import (
	"context"

	"github.com/todennus/oauth2-service/usecase/dto"
)

type OAuth2FlowUsecase interface {
	Authorize(ctx context.Context, req *dto.OAuth2AuthorizeRequest) (*dto.OAuth2AuthorizeResponse, error)
	Token(ctx context.Context, req *dto.OAuth2TokenRequest) (*dto.OAuth2TokenResponse, error)
}

type OAuth2AuthenticationUsecase interface {
	AuthenticationCallback(
		ctx context.Context,
		req *dto.OAuth2AuthenticationCallbackRequest,
	) (*dto.OAuth2AuthenticationCallbackResponse, error)
	SessionUpdate(
		ctx context.Context,
		req *dto.OAuth2SessionUpdateRequest,
	) (*dto.OAuth2SessionUpdateResponse, error)
}

type OAuth2ConsentUsecase interface {
	GetConsent(ctx context.Context, req *dto.OAuth2GetConsentRequest) (*dto.OAuth2GetConsentResponse, error)
	UpdateConsent(
		ctx context.Context,
		req *dto.OAuth2UpdateConsentRequest,
	) (*dto.OAUth2UpdateConsentResponse, error)
}

package usecase

import (
	"context"
	"errors"

	"github.com/todennus/oauth2-service/domain"
	"github.com/todennus/oauth2-service/usecase/abstraction"
	"github.com/todennus/oauth2-service/usecase/dto"
	"github.com/todennus/shared/errordef"
	"github.com/todennus/shared/scopedef"
	"github.com/todennus/x/xcontext"
	"github.com/todennus/x/xerror"
)

type OAuth2ConsentUsecase struct {
	oauth2ConsentDomain abstraction.OAuth2ConsentDomain
	oauth2SessionDomain abstraction.OAuth2SessionDomain

	sessionRepo       abstraction.SessionRepository
	oauth2ClientRepo  abstraction.OAuth2ClientRepository
	oauth2CodeRepo    abstraction.OAuth2AuthorizationCodeRepository
	oauth2ConsentRepo abstraction.OAuth2ConsentRepository
}

func NewOAuth2ConsentUsecase(
	oauth2ConsentDomain abstraction.OAuth2ConsentDomain,
	oauth2SessionDomain abstraction.OAuth2SessionDomain,
	oauth2ClientRepo abstraction.OAuth2ClientRepository,
	sessionRepo abstraction.SessionRepository,
	oauth2CodeRepo abstraction.OAuth2AuthorizationCodeRepository,
	oauth2ConsentRepo abstraction.OAuth2ConsentRepository,
) *OAuth2ConsentUsecase {
	return &OAuth2ConsentUsecase{
		oauth2ConsentDomain: oauth2ConsentDomain,
		oauth2SessionDomain: oauth2SessionDomain,

		sessionRepo:       sessionRepo,
		oauth2ClientRepo:  oauth2ClientRepo,
		oauth2CodeRepo:    oauth2CodeRepo,
		oauth2ConsentRepo: oauth2ConsentRepo,
	}
}

func (usecase *OAuth2ConsentUsecase) GetConsent(
	ctx context.Context,
	req *dto.OAuth2GetConsentRequest,
) (*dto.OAuth2GetConsentResponse, error) {
	store, err := usecase.oauth2CodeRepo.LoadAuthorizationStore(ctx, req.AuthorizationID)
	if err != nil {
		if errors.Is(err, errordef.ErrNotFound) {
			return nil, xerror.Enrich(errordef.ErrRequestInvalid, "not found authorization id")
		}

		return nil, errordef.ErrServer.Hide(err, "failed-to-load-authorization-store", "aid", req.AuthorizationID)
	}

	client, err := usecase.oauth2ClientRepo.GetByID(ctx, store.ClientID)
	if err != nil {
		return nil, errordef.ErrServer.Hide(err, "failed-to-load-client", "cid", store.ClientID)
	}

	return dto.NewOAuth2GetConsentResponse(client, store.Scope), nil
}

func (usecase *OAuth2ConsentUsecase) UpdateConsent(
	ctx context.Context,
	req *dto.OAuth2UpdateConsentRequest,
) (*dto.OAUth2UpdateConsentResponse, error) {
	store, err := usecase.oauth2CodeRepo.LoadAuthorizationStore(ctx, req.AuthorizationID)
	if err != nil {
		if errors.Is(err, errordef.ErrNotFound) {
			return nil, xerror.Enrich(errordef.ErrRequestInvalid, "not found authorization id %s", req.AuthorizationID)
		}

		return nil, errordef.ErrServer.Hide(err, "failed-to-load-authorization-store", "aid", req.AuthorizationID)
	}

	if err := usecase.oauth2CodeRepo.DeleteAuthorizationStore(ctx, req.AuthorizationID); err != nil {
		xcontext.Logger(ctx).Warn("failed-to-delete-authorization-store", "aid", req.AuthorizationID)
	}

	userID, err := getAuthenticatedUser(ctx, usecase.sessionRepo, usecase.oauth2SessionDomain)
	if err != nil {
		return nil, err
	}

	var result *domain.OAuth2ConsentResult

	if req.Accept {
		userScope := scopedef.Engine.ParseScopes(req.UserScope)
		result = usecase.oauth2ConsentDomain.NewConsentAcceptedResult(userID, store.ClientID, userScope)

		consent := usecase.oauth2ConsentDomain.NewConsent(userID, store.ClientID, userScope)
		if err := usecase.oauth2ConsentRepo.Upsert(ctx, consent); err != nil {
			return nil, errordef.ErrServer.Hide(err, "failed-to-new-or-update-consent")
		}
	} else {
		result = usecase.oauth2ConsentDomain.NewConsentDeniedResult(userID, store.ClientID)
	}

	if err := usecase.oauth2ConsentRepo.SaveResult(ctx, result); err != nil {
		return nil, errordef.ErrServer.Hide(err, "failed-to-save-consent-result")
	}

	return dto.NewOAUth2UpdateConsentResponse(store), nil
}

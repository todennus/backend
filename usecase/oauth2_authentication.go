package usecase

import (
	"context"
	"errors"

	"github.com/todennus/oauth2-service/domain"
	"github.com/todennus/oauth2-service/usecase/abstraction"
	"github.com/todennus/oauth2-service/usecase/dto"
	"github.com/todennus/shared/errordef"
	"github.com/todennus/x/xcontext"
	"github.com/todennus/x/xerror"
)

type OAuth2AuthenticationUsecase struct {
	idpSecret string

	oauth2SessionDomain abstraction.OAuth2SessionDomain

	userRepo       abstraction.UserRepository
	sessionRepo    abstraction.SessionRepository
	oauth2CodeRepo abstraction.OAuth2AuthorizationCodeRepository
}

func NewOAuth2AuthenticationUsecase(
	idpSecret string,
	oauth2SessionDomain abstraction.OAuth2SessionDomain,
	userRepo abstraction.UserRepository,
	sessionRepo abstraction.SessionRepository,
	oauth2CodeRepo abstraction.OAuth2AuthorizationCodeRepository,
) *OAuth2AuthenticationUsecase {
	return &OAuth2AuthenticationUsecase{
		idpSecret: idpSecret,

		oauth2SessionDomain: oauth2SessionDomain,

		userRepo:       userRepo,
		sessionRepo:    sessionRepo,
		oauth2CodeRepo: oauth2CodeRepo,
	}
}

func (usecase *OAuth2AuthenticationUsecase) AuthenticationCallback(
	ctx context.Context,
	req *dto.OAuth2AuthenticationCallbackRequest,
) (*dto.OAuth2AuthenticationCallbackResponse, error) {
	if req.Secret != usecase.idpSecret {
		return nil, xerror.Enrich(errordef.ErrCredentialsInvalid, "incorrect idp secret")
	}

	store, err := usecase.oauth2CodeRepo.LoadAuthorizationStore(ctx, req.AuthorizationID)
	if err != nil {
		if errors.Is(err, errordef.ErrNotFound) {
			return nil, xerror.Enrich(errordef.ErrRequestInvalid, "not found authorization id")
		}

		return nil, errordef.ErrServer.Hide(err, "failed-to-load-authorization-store", "aid", req.AuthorizationID)
	}

	if !store.IsOpen {
		return nil, xerror.Enrich(errordef.ErrRequestInvalid, "callback api closed for this authorization id")
	}

	store.IsOpen = false
	if err := usecase.oauth2CodeRepo.SaveAuthorizationStore(ctx, store); err != nil {
		return nil, errordef.ErrServer.Hide(err, "failed-to-update-authorization-store")
	}

	var authResult *domain.OAuth2AuthenticationResult
	if req.Success {
		if _, err := usecase.userRepo.GetByID(ctx, req.UserID); err != nil {
			if errors.Is(err, errordef.ErrNotFound) {
				return nil, xerror.Enrich(errordef.ErrNotFound, "not found user with id %d", req.UserID)
			}

			return nil, errordef.ErrServer.Hide(err, "failed-to-get-user", "uid", req.UserID)
		}

		authResult = usecase.oauth2SessionDomain.NewAuthenticationResultSuccess(
			req.AuthorizationID, req.UserID, req.Username)
	} else {
		authResult = usecase.oauth2SessionDomain.NewAuthenticationResultFailure(
			req.AuthorizationID, req.Error)
	}

	if err := usecase.oauth2CodeRepo.SaveAuthenticationResult(ctx, authResult); err != nil {
		return nil, errordef.ErrServer.Hide(err, "failed-to-save-auth-result")
	}

	xcontext.Logger(ctx).Debug("saved-auth-result", "result", authResult.Ok, "uid", authResult.UserID)
	return &dto.OAuth2AuthenticationCallbackResponse{AuthenticationID: authResult.ID}, nil
}

func (usecase *OAuth2AuthenticationUsecase) SessionUpdate(
	ctx context.Context,
	req *dto.OAuth2SessionUpdateRequest,
) (*dto.OAuth2SessionUpdateResponse, error) {
	authResult, err := usecase.oauth2CodeRepo.LoadAuthenticationResult(ctx, req.AuthenticationID)
	if err != nil {
		if errors.Is(err, errordef.ErrNotFound) {
			return nil, xerror.Enrich(errordef.ErrRequestInvalid, "invalid authentication id")
		}

		return nil, errordef.ErrServer.Hide(err, "failed-to-load-auth-result", "aid", req.AuthenticationID)
	}

	if err := usecase.oauth2CodeRepo.DeleteAuthenticationResult(ctx, req.AuthenticationID); err != nil {
		xcontext.Logger(ctx).Warn("failed-to-delete-auth-result", "err", err, "aid", req.AuthenticationID)
	}

	store, err := usecase.oauth2CodeRepo.LoadAuthorizationStore(ctx, authResult.AuthorizationID)
	if err != nil {
		return nil, errordef.ErrServer.Hide(err, "failed-to-load-authorization-store", "aid", authResult.AuthorizationID)
	}

	if err := usecase.oauth2CodeRepo.DeleteAuthorizationStore(ctx, authResult.AuthorizationID); err != nil {
		xcontext.Logger(ctx).Warn("failed-to-delete-authorization-store", "aid", authResult.AuthorizationID)
	}

	var session *domain.Session
	if authResult.Ok {
		session = usecase.oauth2SessionDomain.NewSession(authResult.UserID)
	} else {
		session = usecase.oauth2SessionDomain.InvalidateSession(domain.SessionStateFailedAuthentication)
	}

	xcontext.Logger(ctx).Debug("save-session", "state", session.State)
	if err = usecase.sessionRepo.Save(ctx, session); err != nil {
		return nil, errordef.ErrServer.Hide(err, "failed-to-save-session", "aid", authResult.AuthorizationID)
	}

	return dto.NewOAuth2SessionUpdateResponse(store), nil
}

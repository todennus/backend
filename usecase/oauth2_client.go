package usecase

import (
	"context"
	"errors"

	"github.com/todennus/oauth2-service/usecase/abstraction"
	"github.com/todennus/oauth2-service/usecase/dto"
	"github.com/todennus/shared/enumdef"
	"github.com/todennus/shared/errordef"
	"github.com/todennus/shared/scopedef"
	"github.com/todennus/x/lock"
	"github.com/todennus/x/xcontext"
	"github.com/todennus/x/xerror"
)

type OAuth2ClientUsecase struct {
	isNoClient      bool
	firstClientLock lock.Locker

	oauth2ClientDomain abstraction.OAuth2ClientDomain

	userRepo         abstraction.UserRepository
	oauth2ClientRepo abstraction.OAuth2ClientRepository
}

func NewOAuth2ClientUsecase(
	locker lock.Locker,
	oauth2ClientDomain abstraction.OAuth2ClientDomain,
	userRepo abstraction.UserRepository,
	oauth2ClientRepo abstraction.OAuth2ClientRepository,
) *OAuth2ClientUsecase {
	return &OAuth2ClientUsecase{
		isNoClient:         true,
		firstClientLock:    locker,
		oauth2ClientDomain: oauth2ClientDomain,
		userRepo:           userRepo,
		oauth2ClientRepo:   oauth2ClientRepo,
	}
}

func (usecase *OAuth2ClientUsecase) Create(
	ctx context.Context,
	req *dto.OAuth2ClientCreateRequest,
) (*dto.OAuth2ClientCreateResponse, error) {
	requiredScope := scopedef.Engine.New(scopedef.Actions.Write.Create, scopedef.Resources.Client)
	if !xcontext.Scope(ctx).Contains(requiredScope) {
		return nil, xerror.Enrich(errordef.ErrForbidden, "insufficient scope, require %s", requiredScope)
	}

	userID := xcontext.RequestUserID(ctx)
	client, secret, err := usecase.oauth2ClientDomain.NewClient(userID, req.Name, req.IsConfidential)
	if err != nil {
		return nil, errordef.Domain.Event(err, "failed-to-new-client").Enrich(errordef.ErrRequestInvalid).Error()
	}

	if err = usecase.oauth2ClientRepo.Create(ctx, client); err != nil {
		return nil, errordef.ErrServer.Hide(err, "failed-to-create-client")
	}

	return dto.NewOAuth2ClientCreateResponse(client, secret), nil
}

func (usecase *OAuth2ClientUsecase) CreateByAdmin(
	ctx context.Context,
	req *dto.OAuth2ClientCreateFirstRequest,
) (*dto.OAuth2ClientCreateByAdminResponse, error) {
	if !usecase.isNoClient {
		return nil, xerror.Enrich(errordef.ErrNotFound, "this api is only openned for creating the first client")
	}

	if err := usecase.firstClientLock.Lock(ctx); err != nil {
		return nil, errordef.ErrServer.Hide(err, "failed-to-lock-first-client-flow")
	}
	defer usecase.firstClientLock.Unlock(ctx)

	count, err := usecase.oauth2ClientRepo.Count(ctx)
	if err != nil {
		return nil, errordef.ErrServer.Hide(err, "failed-to-count-client")
	}

	if count > 0 {
		usecase.isNoClient = false
		return nil, xerror.Enrich(errordef.ErrNotFound, "this api is only openned for creating the first client")
	}

	user, err := usecase.userRepo.Validate(ctx, req.Username, req.Password)
	if err != nil {
		if errors.Is(err, errordef.ErrCredentialsInvalid) {
			return nil, xerror.Enrich(errordef.ErrCredentialsInvalid, "invalid username or password")
		}

		return nil, errordef.ErrServer.Hide(err, "failed-to-validate-user")
	}

	if user.Role != enumdef.UserRoleAdmin {
		return nil, xerror.Enrich(errordef.ErrForbidden, "require admin")
	}

	client, secret, err := usecase.oauth2ClientDomain.NewClient(user.ID, req.Name, true)
	if err != nil {
		return nil, errordef.Domain.Event(err, "failed-to-new-client").Enrich(errordef.ErrRequestInvalid).Error()
	}

	if err = usecase.oauth2ClientRepo.Create(ctx, client); err != nil {
		return nil, errordef.ErrServer.Hide(err, "failed-to-create-first-client")
	}

	usecase.isNoClient = false
	return dto.NewOAuth2ClientCreateFirstResponse(ctx, client, secret), nil
}

func (usecase *OAuth2ClientUsecase) Get(
	ctx context.Context,
	req *dto.OAuth2ClientGetRequest,
) (*dto.OAuth2ClientGetResponse, error) {
	client, err := usecase.oauth2ClientRepo.GetByID(ctx, req.ClientID.Int64())
	if err != nil {
		if errors.Is(err, errordef.ErrNotFound) {
			return nil, xerror.Enrich(errordef.ErrClientInvalid, "not found client")
		}

		return nil, errordef.ErrServer.Hide(err, "failed-to-get-client", "cid", req.ClientID)
	}

	return dto.NewOAuth2ClientGetResponse(ctx, client), nil
}

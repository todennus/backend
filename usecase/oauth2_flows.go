package usecase

import (
	"context"
	"errors"
	"time"

	"github.com/todennus/oauth2-service/domain"
	"github.com/todennus/oauth2-service/usecase/abstraction"
	"github.com/todennus/oauth2-service/usecase/dto"
	"github.com/todennus/shared/errordef"
	"github.com/todennus/shared/scopedef"
	"github.com/todennus/shared/tokendef"
	"github.com/todennus/x/scope"
	"github.com/todennus/x/token"
	"github.com/todennus/x/xcontext"
	"github.com/todennus/x/xerror"
	"github.com/todennus/x/xhttp"
	"github.com/xybor-x/snowflake"
)

const (
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypePassword          = "password"
	GrantTypeClientCredentials = "client_credentials"
	GrantTypeRefreshToken      = "refresh_token"

	// TODO: Support later
	GrantTypeDevice = "urn:ietf:params:oauth:grant-type:device_code"
)

const (
	ResponseTypeCode    = "code"
	ResponseTypeToken   = "token"
	ResponseTypeIDToken = "id_token"
)

type OAuth2FlowUsecase struct {
	tokenEngine token.Engine

	idpLoginURL string
	idpSecret   string

	oauth2ClientDomain  abstraction.OAuth2ClientDomain
	oauth2FlowDomain    abstraction.OAuth2FlowDomain
	oauth2ConsentDomain abstraction.OAuth2ConsentDomain

	userRepo          abstraction.UserRepository
	refreshTokenRepo  abstraction.RefreshTokenRepository
	sessionRepo       abstraction.SessionRepository
	oauth2ClientRepo  abstraction.OAuth2ClientRepository
	oauth2CodeRepo    abstraction.OAuth2AuthorizationCodeRepository
	oauth2ConsentRepo abstraction.OAuth2ConsentRepository
}

func NewOAuth2Usecase(
	tokenEngine token.Engine,
	idpLoginURL string,
	idpSecret string,
	oauth2FlowDomain abstraction.OAuth2FlowDomain,
	oauth2ClientDomain abstraction.OAuth2ClientDomain,
	oauth2ConsentDomain abstraction.OAuth2ConsentDomain,
	userRepo abstraction.UserRepository,
	refreshTokenRepo abstraction.RefreshTokenRepository,
	oauth2ClientRepo abstraction.OAuth2ClientRepository,
	sessionRepo abstraction.SessionRepository,
	oauth2CodeRepo abstraction.OAuth2AuthorizationCodeRepository,
	oauth2ConsentRepo abstraction.OAuth2ConsentRepository,
) *OAuth2FlowUsecase {
	return &OAuth2FlowUsecase{
		tokenEngine: tokenEngine,

		idpLoginURL: idpLoginURL,
		idpSecret:   idpSecret,

		oauth2FlowDomain:    oauth2FlowDomain,
		oauth2ClientDomain:  oauth2ClientDomain,
		oauth2ConsentDomain: oauth2ConsentDomain,

		userRepo:          userRepo,
		refreshTokenRepo:  refreshTokenRepo,
		sessionRepo:       sessionRepo,
		oauth2ClientRepo:  oauth2ClientRepo,
		oauth2CodeRepo:    oauth2CodeRepo,
		oauth2ConsentRepo: oauth2ConsentRepo,
	}
}

func (usecase *OAuth2FlowUsecase) Authorize(
	ctx context.Context,
	req *dto.OAuth2AuthorizeRequest,
) (*dto.OAuth2AuthorizeResponse, error) {
	if _, err := xhttp.ParseURL(req.RedirectURI); err != nil {
		return nil, xerror.Enrich(errordef.ErrRequestInvalid, "invalid redirect uri")
	}

	client, err := usecase.oauth2ClientRepo.GetByID(ctx, req.ClientID.Int64())
	if err != nil {
		if errors.Is(err, errordef.ErrNotFound) {
			return nil, xerror.Enrich(errordef.ErrClientInvalid, "client is not found")
		}

		return nil, errordef.ErrServer.Hide(err, "failed-to-get-client", "cid", req.ClientID)
	}

	requestedScope := scopedef.Engine.ParseScopes(req.Scope)
	if err := usecase.oauth2FlowDomain.ValidateRequestedScope(requestedScope, client); err != nil {
		return nil, errordef.Domain.Event(err, "failed-to-validate-requested-scope").Enrich(errordef.ErrScopeInvalid).Error()
	}

	switch req.ResponseType {
	case ResponseTypeCode:
		return usecase.handleAuthorizeCodeFlow(ctx, req, requestedScope)
	default:
		return nil, xerror.Enrich(errordef.ErrRequestInvalid, "not support response type %s", req.ResponseType)
	}
}

func (usecase *OAuth2FlowUsecase) Token(
	ctx context.Context,
	req *dto.OAuth2TokenRequest,
) (*dto.OAuth2TokenResponse, error) {
	client, err := usecase.oauth2ClientRepo.GetByID(ctx, req.ClientID.Int64())
	if err != nil {
		if errors.Is(err, errordef.ErrNotFound) {
			return nil, xerror.Enrich(errordef.ErrClientInvalid, "client is not found")
		}

		return nil, errordef.ErrServer.Hide(err, "failed-to-get-client", "cid", req.ClientID)
	}

	switch req.GrantType {
	case GrantTypeAuthorizationCode:
		return usecase.handleTokenCodeFlow(ctx, req, client)
	case GrantTypePassword:
		return usecase.handleTokenPasswordFlow(ctx, req, client)
	case GrantTypeRefreshToken:
		return usecase.handleTokenRefreshTokenFlow(ctx, req, client)
	default:
		return nil, xerror.Enrich(errordef.ErrRequestInvalid, "not support grant type %s", req.GrantType)
	}
}

func (usecase *OAuth2FlowUsecase) AuthenticationCallback(
	ctx context.Context,
	req *dto.OAuth2AuthenticationCallbackRequest,
) (*dto.OAuth2AuthenticationCallbackResponse, error) {
	if req.Secret != usecase.idpSecret {
		return nil, xerror.Enrich(errordef.ErrUnauthenticated, "incorrect idp secret")
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
		if _, err := usecase.userRepo.GetByID(ctx, req.UserID.Int64()); err != nil {
			if errors.Is(err, errordef.ErrNotFound) {
				return nil, xerror.Enrich(errordef.ErrNotFound, "not found user with id %d", req.UserID)
			}

			return nil, errordef.ErrServer.Hide(err, "failed-to-get-user", "uid", req.UserID)
		}

		authResult = usecase.oauth2FlowDomain.NewAuthenticationResultSuccess(
			req.AuthorizationID, req.UserID, req.Username)
	} else {
		authResult = usecase.oauth2FlowDomain.NewAuthenticationResultFailure(
			req.AuthorizationID, req.Error)
	}

	if err := usecase.oauth2CodeRepo.SaveAuthenticationResult(ctx, authResult); err != nil {
		return nil, errordef.ErrServer.Hide(err, "failed-to-save-auth-result")
	}

	xcontext.Logger(ctx).Debug("saved-auth-result", "result", authResult.Ok, "uid", authResult.UserID)
	return &dto.OAuth2AuthenticationCallbackResponse{AuthenticationID: authResult.ID}, nil
}

func (usecase *OAuth2FlowUsecase) SessionUpdate(
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
		session = usecase.oauth2FlowDomain.NewSession(authResult.UserID)
	} else {
		session = usecase.oauth2FlowDomain.InvalidateSession(domain.SessionStateFailedAuthentication)
	}

	xcontext.Logger(ctx).Debug("save-session", "state", session.State)
	if err = usecase.sessionRepo.Save(ctx, session); err != nil {
		return nil, errordef.ErrServer.Hide(err, "failed-to-save-session", "aid", authResult.AuthorizationID)
	}

	return dto.NewOAuth2SessionUpdateResponse(store), nil
}

func (usecase *OAuth2FlowUsecase) GetConsent(
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

	client, err := usecase.oauth2ClientRepo.GetByID(ctx, store.ClientID.Int64())
	if err != nil {
		return nil, errordef.ErrServer.Hide(err, "failed-to-load-client", "cid", store.ClientID)
	}

	return dto.NewOAuth2GetConsentResponse(client, store.Scope), nil
}

func (usecase *OAuth2FlowUsecase) UpdateConsent(
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

	userID, err := usecase.getAuthenticatedUser(ctx)
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

func (usecase *OAuth2FlowUsecase) handleAuthorizeCodeFlow(
	ctx context.Context,
	req *dto.OAuth2AuthorizeRequest,
	requestedScope scope.Scopes,
) (*dto.OAuth2AuthorizeResponse, error) {
	userID, err := usecase.getAuthenticatedUser(ctx)
	if err != nil {
		return nil, err
	}

	if userID == 0 {
		store, err := usecase.storeAuthorization(ctx, req, requestedScope)
		if err != nil {
			return nil, err
		}

		return dto.NewOAuth2AuthorizeResponseRedirectToIdP(usecase.idpLoginURL, store.ID), nil
	}

	resp, consentScope, err := usecase.validateConsentResult(ctx, userID.Int64(), req, requestedScope)
	if err != nil || resp != nil {
		return resp, err
	}

	code := usecase.oauth2FlowDomain.NewAuthorizationCode(
		userID, req.ClientID, consentScope,
		req.CodeChallenge, req.CodeChallengeMethod,
	)
	if err = usecase.oauth2CodeRepo.SaveAuthorizationCode(ctx, code); err != nil {
		return nil, errordef.ErrServer.Hide(err, "failed-to-save-authorization-code")
	}

	return dto.NewOAuth2AuthorizeResponseWithCode(code.Code), nil
}

func (usecase *OAuth2FlowUsecase) handleTokenCodeFlow(
	ctx context.Context,
	req *dto.OAuth2TokenRequest,
	client *domain.OAuth2Client,
) (*dto.OAuth2TokenResponse, error) {
	code, err := usecase.oauth2CodeRepo.LoadAuthorizationCode(ctx, req.Code)
	if err != nil {
		if errors.Is(err, errordef.ErrNotFound) {
			return nil, xerror.Enrich(errordef.ErrTokenInvalidGrant, "invalid code")
		}

		return nil, errordef.ErrServer.Hide(err, "failed-to-load-code", "code", req.Code)
	}

	if err := usecase.oauth2CodeRepo.DeleteAuthorizationCode(ctx, req.Code); err != nil {
		xcontext.Logger(ctx).Warn("failed-to-delete-authorization-code", "err", err)
	}

	if code.CodeChallenge == "" {
		err := usecase.oauth2ClientDomain.ValidateClient(
			client, req.ClientID, req.ClientSecret, domain.RequireConfidential)
		if err != nil {
			return nil, xerror.Enrich(errordef.ErrClientInvalid, "failed due to invalid client credentials").
				Hide(err, "validate-client-failed")
		}
	} else {
		if !usecase.oauth2FlowDomain.ValidateCodeChallenge(req.CodeVerifier, code.CodeChallenge, code.CodeChallengeMethod) {
			return nil, xerror.Enrich(errordef.ErrTokenInvalidGrant, "incorrect code verifier")
		}
	}

	user, err := usecase.userRepo.GetByID(ctx, code.UserID.Int64())
	if err != nil {
		return nil, errordef.ErrServer.Hide(err, "failed-to-get-user", "uid", code.UserID)
	}

	return usecase.completeRegularTokenFlow(ctx, "", code.Scope, user)
}

func (usecase *OAuth2FlowUsecase) handleTokenPasswordFlow(
	ctx context.Context,
	req *dto.OAuth2TokenRequest,
	client *domain.OAuth2Client,
) (*dto.OAuth2TokenResponse, error) {

	err := usecase.oauth2ClientDomain.ValidateClient(
		client, req.ClientID, req.ClientSecret, domain.RequireConfidential)
	if err != nil {
		return nil, xerror.Enrich(errordef.ErrClientInvalid, "failed due to invalid client credentials").
			Hide(err, "validate-client-failed")
	}

	// Get the user information.
	user, err := usecase.userRepo.Validate(ctx, req.Username, req.Password)
	if err != nil {
		if errors.Is(err, errordef.ErrCredentialsInvalid) {
			return nil, xerror.Enrich(errordef.ErrCredentialsInvalid, "invalid username or password")
		}

		return nil, errordef.ErrServer.Hide(err, "failed-to-validate-user")
	}

	requestedScope := scopedef.Engine.ParseScopes(req.Scope)
	if err := usecase.oauth2FlowDomain.ValidateRequestedScope(requestedScope, client); err != nil {
		return nil, errordef.Domain.Event(err, "failed-to-validate-requested-scope").Enrich(errordef.ErrScopeInvalid).Error()
	}

	return usecase.completeRegularTokenFlow(ctx, "", requestedScope, user)
}

func (usecase *OAuth2FlowUsecase) handleTokenRefreshTokenFlow(
	ctx context.Context,
	req *dto.OAuth2TokenRequest,
	client *domain.OAuth2Client,
) (*dto.OAuth2TokenResponse, error) {
	err := usecase.oauth2ClientDomain.ValidateClient(
		client, req.ClientID, req.ClientSecret, domain.DependOnClientConfidential)
	if err != nil {
		return nil, xerror.Enrich(errordef.ErrClientInvalid, "failed due to invalid client credentials").
			Hide(err, "validate-client-failed")
	}

	// Check the current refresh token
	curRefreshToken := &tokendef.OAuth2RefreshToken{}
	ok, err := usecase.tokenEngine.Validate(ctx, req.RefreshToken, curRefreshToken)
	if err != nil {
		return nil, errordef.ErrServer.Hide(err, "failed-to-validate-refresh-token")
	}

	if !ok {
		return nil, xerror.Enrich(errordef.ErrTokenInvalidGrant, "refresh token is invalid or expired")
	}

	// Generate the next refresh token.
	domainCurRefreshToken, err := dto.OAuth2RefreshTokenToDomain(curRefreshToken)
	if err != nil {
		return nil, errordef.ErrServer.Hide(err, "failed-to-convert-refresh-token")
	}

	refreshToken := usecase.oauth2FlowDomain.NextRefreshToken(domainCurRefreshToken)

	// Get the user.
	user, err := usecase.userRepo.GetByID(ctx, refreshToken.Metadata.Subject.Int64())
	if err != nil {
		return nil, errordef.ErrServer.Hide(err, "failed-to-get-user", "uid", refreshToken.Metadata.Subject)
	}

	// Generate access token.
	accessToken := usecase.oauth2FlowDomain.NewAccessToken(
		domainCurRefreshToken.Metadata.Audience, domainCurRefreshToken.Scope, user)

	// Serialize both tokens.
	accessTokenString, refreshTokenString, err := usecase.serializeAccessAndRefreshTokens(ctx, accessToken, refreshToken)
	if err != nil {
		return nil, err
	}

	// Store the seq number again.
	err = usecase.refreshTokenRepo.UpdateByRefreshTokenID(
		ctx,
		domainCurRefreshToken.Metadata.ID.Int64(),
		accessToken.Metadata.ID.Int64(),
		domainCurRefreshToken.SequenceNumber,
	)
	if err != nil {
		if errors.Is(err, errordef.ErrNotFound) {
			err = usecase.refreshTokenRepo.DeleteByRefreshTokenID(ctx, domainCurRefreshToken.Metadata.ID.Int64())
			if err != nil {
				xcontext.Logger(ctx).Warn("failed-to-delete-token", "err", err)
			}

			return nil, xerror.Enrich(errordef.ErrTokenInvalidGrant, "refresh token was stolen")
		}

		return nil, errordef.ErrServer.Hide(err, "failed-to-update-token")
	}

	return &dto.OAuth2TokenResponse{
		AccessToken:  accessTokenString,
		TokenType:    usecase.tokenEngine.Type(),
		ExpiresIn:    usecase.getExpiresIn(accessToken.Metadata),
		RefreshToken: refreshTokenString,
		Scope:        domainCurRefreshToken.Scope.String(),
	}, nil
}

func (usecase *OAuth2FlowUsecase) serializeAccessAndRefreshTokens(
	ctx context.Context,
	accessToken *domain.OAuth2AccessToken,
	refreshToken *domain.OAuth2RefreshToken,
) (string, string, error) {
	accessTokenString, err := usecase.tokenEngine.Generate(ctx, dto.OAuth2AccessTokenFromDomain(accessToken))
	if err != nil {
		return "", "", errordef.ErrServer.Hide(err, "failed-to-generate-access-token")
	}

	refreshTokenString, err := usecase.tokenEngine.Generate(ctx, dto.OAuth2RefreshTokenFromDomain(refreshToken))
	if err != nil {
		return "", "", errordef.ErrServer.Hide(err, "failed-to-generate-refresh-token")
	}

	return accessTokenString, refreshTokenString, nil
}

func (usecase *OAuth2FlowUsecase) completeRegularTokenFlow(
	ctx context.Context,
	aud string,
	scope scope.Scopes,
	user *domain.User,
) (*dto.OAuth2TokenResponse, error) {
	accessToken := usecase.oauth2FlowDomain.NewAccessToken(aud, scope, user)
	refreshToken := usecase.oauth2FlowDomain.NewRefreshToken(aud, scope, user.ID)

	// Serialize both tokens.
	accessTokenString, refreshTokenString, err := usecase.serializeAccessAndRefreshTokens(ctx, accessToken, refreshToken)
	if err != nil {
		return nil, err
	}

	// Store refresh token information.
	err = usecase.refreshTokenRepo.Create(
		ctx, refreshToken.Metadata.ID.Int64(), accessToken.Metadata.ID.Int64(), 0)
	if err != nil {
		return nil, errordef.ErrServer.Hide(err, "failed-to-save-refresh-token")
	}

	return &dto.OAuth2TokenResponse{
		AccessToken:  accessTokenString,
		TokenType:    usecase.tokenEngine.Type(),
		ExpiresIn:    usecase.getExpiresIn(accessToken.Metadata),
		RefreshToken: refreshTokenString,
		Scope:        scope.String(),
	}, nil
}

func (usecase *OAuth2FlowUsecase) getAuthenticatedUser(ctx context.Context) (snowflake.ID, error) {
	session, err := usecase.sessionRepo.Load(ctx)
	if err == nil {
		xcontext.Logger(ctx).Debug("session-state", "state", session.State, "expires_at", session.ExpiresAt)
	} else {
		xcontext.Logger(ctx).Debug("failed-to-load-session", "err", err)
	}

	if err != nil || session.ExpiresAt.Before(time.Now()) || session.State == domain.SessionStateUnauthenticated {
		return 0, nil
	}

	if session.State == domain.SessionStateFailedAuthentication {
		session := usecase.oauth2FlowDomain.InvalidateSession(domain.SessionStateUnauthenticated)
		if err := usecase.sessionRepo.Save(ctx, session); err != nil {
			xcontext.Logger(ctx).Warn("failed-to-save-invalidate-session", "err", err)
		}

		return 0, xerror.Enrich(errordef.ErrAccessDenied, "the user failed to authenticate")
	}

	return session.UserID, nil
}

func (usecase *OAuth2FlowUsecase) storeAuthorization(
	ctx context.Context,
	req *dto.OAuth2AuthorizeRequest,
	scope scope.Scopes,
) (*domain.OAuth2AuthorizationStore, error) {
	store := usecase.oauth2FlowDomain.NewAuthorizationStore(
		req.ResponseType, req.ClientID, scope, req.RedirectURI,
		req.State, req.CodeChallenge, req.CodeChallengeMethod,
	)

	if err := usecase.oauth2CodeRepo.SaveAuthorizationStore(ctx, store); err != nil {
		return nil, errordef.ErrServer.Hide(err, "failed-to-save-session")
	}

	return store, nil
}

func (usecase *OAuth2FlowUsecase) validateConsentResult(
	ctx context.Context,
	userID int64,
	req *dto.OAuth2AuthorizeRequest,
	requestedScope scope.Scopes,
) (*dto.OAuth2AuthorizeResponse, scope.Scopes, error) {
	clientID := req.ClientID.Int64()
	logger := xcontext.Logger(ctx).With("cid", req.ClientID, "uid", userID)

	result, err := usecase.oauth2ConsentRepo.LoadResult(ctx, userID, clientID)
	if err == nil {
		if err := usecase.oauth2ConsentRepo.DeleteResult(ctx, userID, clientID); err != nil {
			logger.Warn("failed-to-delete-failure-consent-result", "err", err)
		}

		if result.ExpiresAt.Before(time.Now()) {
			return usecase.redirectToConsentPage(ctx, req, requestedScope)
		}

		if result.Accepted {
			if !result.Scope.LessThanOrEqual(requestedScope) {
				return nil, nil, xerror.Enrich(errordef.ErrScopeInvalid,
					"user choose more scopes than the request from client")
			}

			for i := range requestedScope {
				if !requestedScope[i].IsOptional() && !result.Scope.Contains(requestedScope[i]) {
					return nil, nil, xerror.Enrich(errordef.ErrScopeInvalid,
						"user denied the required scope %s", requestedScope[i])
				}
			}

			// In case user has just consented with the requested scope (user
			// can choose less scope than the requested one), we need to return
			// the scope which user chose rather than the requested scope.
			return nil, result.Scope, nil
		}

		return nil, nil, xerror.Enrich(errordef.ErrAccessDenied, "user declined to grant access")
	}

	if !errors.Is(err, errordef.ErrNotFound) { // unknown error
		logger.Warn("failed-to-get-consent-record", "err", err)
		return usecase.redirectToConsentPage(ctx, req, requestedScope)
	}

	consent, err := usecase.oauth2ConsentRepo.Get(ctx, userID, clientID)
	if err != nil && !errors.Is(err, errordef.ErrNotFound) {
		logger.Critical("failed-to-get-user", "err", err)
		return usecase.redirectToConsentPage(ctx, req, requestedScope)
	}

	if errors.Is(err, errordef.ErrNotFound) {
		logger.Debug("no-consent")
		return usecase.redirectToConsentPage(ctx, req, requestedScope)
	}

	if err := usecase.oauth2ConsentDomain.ValidateConsent(consent, requestedScope); err != nil {
		logger.Debug("validate-consent-fails", "err", err,
			"requested_scope", requestedScope, "consent_scope", consent.Scope)
		return usecase.redirectToConsentPage(ctx, req, requestedScope)
	}

	// In this case, the requested scope is valid for the previous consented
	// scope.
	return nil, requestedScope, nil
}

func (usecase *OAuth2FlowUsecase) redirectToConsentPage(
	ctx context.Context,
	req *dto.OAuth2AuthorizeRequest,
	requestedScope scope.Scopes,
) (*dto.OAuth2AuthorizeResponse, scope.Scopes, error) {
	store, err := usecase.storeAuthorization(ctx, req, requestedScope)
	if err != nil {
		return nil, nil, err
	}

	return dto.NewOAuth2AuthorizeResponseRedirectToConsent(store.ID), nil, nil
}

func (usecase *OAuth2FlowUsecase) getExpiresIn(metadata *domain.OAuth2TokenMedata) int {
	createdAt := time.UnixMilli(metadata.ID.Time())
	expiresAt := time.Unix(int64(metadata.ExpiresAt), 0)
	return int(expiresAt.Sub(createdAt) / time.Second)
}

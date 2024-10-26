package usecase

import (
	"context"
	"errors"
	"time"

	"github.com/todennus/oauth2-service/domain"
	"github.com/todennus/oauth2-service/usecase/abstraction"
	"github.com/todennus/oauth2-service/usecase/dto"
	"github.com/todennus/shared/enumdef"
	"github.com/todennus/shared/errordef"
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

	oauth2FlowDomain    abstraction.OAuth2FlowDomain
	oauth2ConsentDomain abstraction.OAuth2ConsentDomain
	oauth2TokenDomain   abstraction.OAuth2TokenDomain
	oauth2SessionDomain abstraction.OAuth2SessionDomain

	userRepo          abstraction.UserRepository
	refreshTokenRepo  abstraction.RefreshTokenRepository
	sessionRepo       abstraction.SessionRepository
	oauth2ClientRepo  abstraction.OAuth2ClientRepository
	oauth2CodeRepo    abstraction.OAuth2AuthorizationCodeRepository
	oauth2ConsentRepo abstraction.OAuth2ConsentRepository
}

func NewOAuth2FlowUsecase(
	tokenEngine token.Engine,
	idpLoginURL string,
	oauth2FlowDomain abstraction.OAuth2FlowDomain,
	oauth2ConsentDomain abstraction.OAuth2ConsentDomain,
	oauth2TokenDomain abstraction.OAuth2TokenDomain,
	oauth2SessionDomain abstraction.OAuth2SessionDomain,
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

		oauth2FlowDomain:    oauth2FlowDomain,
		oauth2ConsentDomain: oauth2ConsentDomain,
		oauth2TokenDomain:   oauth2TokenDomain,
		oauth2SessionDomain: oauth2SessionDomain,

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

	if err := usecase.validateClient(ctx, req.ClientID, "", enumdef.NotRequireConfidential, req.Scope); err != nil {
		return nil, err
	}

	switch req.ResponseType {
	case ResponseTypeCode:
		return usecase.handleAuthorizeCodeFlow(ctx, req)
	default:
		return nil, xerror.Enrich(errordef.ErrRequestInvalid, "not support response type %s", req.ResponseType)
	}
}

func (usecase *OAuth2FlowUsecase) Token(
	ctx context.Context,
	req *dto.OAuth2TokenRequest,
) (*dto.OAuth2TokenResponse, error) {
	switch req.GrantType {
	case GrantTypeAuthorizationCode:
		return usecase.handleTokenCodeFlow(ctx, req)
	case GrantTypePassword:
		return usecase.handleTokenPasswordFlow(ctx, req)
	case GrantTypeRefreshToken:
		return usecase.handleTokenRefreshTokenFlow(ctx, req)
	default:
		return nil, xerror.Enrich(errordef.ErrRequestInvalid, "not support grant type %s", req.GrantType)
	}
}

func (usecase *OAuth2FlowUsecase) handleAuthorizeCodeFlow(
	ctx context.Context,
	req *dto.OAuth2AuthorizeRequest,
) (*dto.OAuth2AuthorizeResponse, error) {
	userID, err := getAuthenticatedUser(ctx, usecase.sessionRepo, usecase.oauth2SessionDomain)
	if err != nil {
		return nil, err
	}

	if userID == 0 {
		store, err := usecase.storeAuthorization(ctx, true, req, req.Scope)
		if err != nil {
			return nil, err
		}

		return dto.NewOAuth2AuthorizeResponseRedirectToIdP(usecase.idpLoginURL, store.ID), nil
	}

	resp, consentScope, err := usecase.validateConsentResult(ctx, userID.Int64(), req, req.Scope)
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
) (*dto.OAuth2TokenResponse, error) {
	code, err := usecase.oauth2CodeRepo.LoadAuthorizationCode(ctx, req.Code)
	if err != nil {
		if errors.Is(err, errordef.ErrNotFound) {
			return nil, xerror.Enrich(errordef.ErrOAuth2InvalidGrant, "invalid code")
		}

		return nil, errordef.ErrServer.Hide(err, "failed-to-load-code", "code", req.Code)
	}

	if err := usecase.oauth2CodeRepo.DeleteAuthorizationCode(ctx, req.Code); err != nil {
		xcontext.Logger(ctx).Warn("failed-to-delete-authorization-code", "err", err)
	}

	if code.CodeChallenge == "" {
		err := usecase.validateClient(ctx, req.ClientID, req.ClientSecret, enumdef.RequireConfidential, code.Scope)
		if err != nil {
			return nil, err
		}
	} else {
		if !usecase.oauth2FlowDomain.ValidateCodeChallenge(req.CodeVerifier, code.CodeChallenge, code.CodeChallengeMethod) {
			return nil, xerror.Enrich(errordef.ErrOAuth2InvalidGrant, "incorrect code verifier")
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
) (*dto.OAuth2TokenResponse, error) {
	err := usecase.validateClient(ctx, req.ClientID, req.ClientSecret, enumdef.RequireConfidential, req.Scope)
	if err != nil {
		return nil, err
	}

	// Get the user information.
	user, err := usecase.userRepo.Validate(ctx, req.Username, req.Password)
	if err != nil {
		if errors.Is(err, errordef.ErrCredentialsInvalid) {
			return nil, xerror.Enrich(errordef.ErrCredentialsInvalid, "invalid username or password")
		}

		return nil, errordef.ErrServer.Hide(err, "failed-to-validate-user")
	}

	return usecase.completeRegularTokenFlow(ctx, "", req.Scope, user)
}

func (usecase *OAuth2FlowUsecase) handleTokenRefreshTokenFlow(
	ctx context.Context,
	req *dto.OAuth2TokenRequest,
) (*dto.OAuth2TokenResponse, error) {
	// Check the current refresh token
	curRefreshToken := &tokendef.OAuth2RefreshToken{}
	ok, err := usecase.tokenEngine.Validate(ctx, req.RefreshToken, curRefreshToken)
	if err != nil {
		return nil, errordef.ErrServer.Hide(err, "failed-to-validate-refresh-token")
	}

	if !ok {
		return nil, xerror.Enrich(errordef.ErrOAuth2InvalidGrant, "refresh token is invalid or expired")
	}

	// Generate the next refresh token.
	domainCurRefreshToken, err := dto.OAuth2RefreshTokenToDomain(curRefreshToken)
	if err != nil {
		return nil, errordef.ErrServer.Hide(err, "failed-to-convert-refresh-token")
	}

	err = usecase.validateClient(
		ctx, req.ClientID, req.ClientSecret, enumdef.DependOnClientConfidential, domainCurRefreshToken.Scope)
	if err != nil {
		return nil, err
	}

	refreshToken := usecase.oauth2TokenDomain.NextRefreshToken(domainCurRefreshToken)

	// Get the user.
	user, err := usecase.userRepo.GetByID(ctx, refreshToken.Metadata.Subject.Int64())
	if err != nil {
		return nil, errordef.ErrServer.Hide(err, "failed-to-get-user", "uid", refreshToken.Metadata.Subject)
	}

	// Generate access token.
	accessToken := usecase.oauth2TokenDomain.NewAccessToken(
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

			return nil, xerror.Enrich(errordef.ErrOAuth2InvalidGrant, "refresh token was stolen")
		}

		return nil, errordef.ErrServer.Hide(err, "failed-to-update-token")
	}

	return &dto.OAuth2TokenResponse{
		AccessToken:  accessTokenString,
		TokenType:    usecase.tokenEngine.Type(),
		ExpiresIn:    usecase.getExpiresIn(accessToken.Metadata),
		RefreshToken: refreshTokenString,
		Scope:        domainCurRefreshToken.Scope,
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
	accessToken := usecase.oauth2TokenDomain.NewAccessToken(aud, scope, user)
	refreshToken := usecase.oauth2TokenDomain.NewRefreshToken(aud, scope, user.ID)

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
		Scope:        scope,
	}, nil
}

func (usecase *OAuth2FlowUsecase) storeAuthorization(
	ctx context.Context,
	open bool,
	req *dto.OAuth2AuthorizeRequest,
	scope scope.Scopes,
) (*domain.OAuth2AuthorizationStore, error) {
	store := usecase.oauth2SessionDomain.NewAuthorizationStore(
		open,
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
				return nil, nil, xerror.Enrich(errordef.ErrOAuth2ScopeInvalid,
					"user choose more scopes than the request from client")
			}

			for i := range requestedScope {
				if !requestedScope[i].IsOptional() && !result.Scope.Contains(requestedScope[i]) {
					return nil, nil, xerror.Enrich(errordef.ErrOAuth2ScopeInvalid,
						"user denied the required scope %s", requestedScope[i])
				}
			}

			// In case user has just consented with the requested scope (user
			// can choose less scope than the requested one), we need to return
			// the scope which user chose rather than the requested scope.
			return nil, result.Scope, nil
		}

		return nil, nil, xerror.Enrich(errordef.ErrOAuth2AccessDenied, "user declined to grant access")
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
	store, err := usecase.storeAuthorization(ctx, false, req, requestedScope)
	if err != nil {
		return nil, nil, err
	}

	return dto.NewOAuth2AuthorizeResponseRedirectToConsent(store.ID), nil, nil
}

func (usecase *OAuth2FlowUsecase) validateClient(
	ctx context.Context,
	clientID snowflake.ID,
	clientSecret string,
	requirement enumdef.ConfidentialRequirementType,
	requestedScope scope.Scopes,
) error {
	err := usecase.oauth2ClientRepo.Validate(
		ctx, clientID.Int64(), clientSecret, requirement, requestedScope.String())
	if err != nil {
		if errors.Is(err, errordef.ErrNotFound) {
			return xerror.Enrich(errordef.ErrOAuth2ClientInvalid, "not found client").
				Hide(err, "failed-to-validate-client")
		}

		if errors.Is(err, errordef.ErrOAuth2ScopeInvalid) {
			return xerror.Enrich(errordef.ErrOAuth2ScopeInvalid,
				"the requested scope exceeds the client allowed scope").Hide(err, "failed-to-validate-client")
		}

		if errors.Is(err, errordef.ErrOAuth2ClientInvalid) {
			return xerror.Enrich(errordef.ErrOAuth2ClientInvalid, "unsupported client type").
				Hide(err, "failed-to-validate-client")
		}

		if errors.Is(err, errordef.ErrUnauthenticated) {
			return xerror.Enrich(errordef.ErrOAuth2ClientInvalid, "client credentials is incorrect").
				Hide(err, "failed-to-validate-client")
		}

		return errordef.ErrServer.Hide(err, "failed-to-validate-client")
	}

	return nil
}

func (usecase *OAuth2FlowUsecase) getExpiresIn(metadata *domain.OAuth2TokenMedata) int {
	createdAt := time.UnixMilli(metadata.ID.Time())
	expiresAt := time.Unix(int64(metadata.ExpiresAt), 0)
	return int(expiresAt.Sub(createdAt) / time.Second)
}

func getAuthenticatedUser(
	ctx context.Context,
	sessionRepo abstraction.SessionRepository,
	sessionDomain abstraction.OAuth2SessionDomain,
) (snowflake.ID, error) {
	session, err := sessionRepo.Load(ctx)
	if err == nil {
		xcontext.Logger(ctx).Debug("session-state", "state", session.State, "expires_at", session.ExpiresAt)
	} else {
		xcontext.Logger(ctx).Debug("failed-to-load-session", "err", err)
	}

	if err != nil || session.ExpiresAt.Before(time.Now()) || session.State == domain.SessionStateUnauthenticated {
		return 0, nil
	}

	if session.State == domain.SessionStateFailedAuthentication {
		session := sessionDomain.InvalidateSession(domain.SessionStateUnauthenticated)
		if err := sessionRepo.Save(ctx, session); err != nil {
			xcontext.Logger(ctx).Warn("failed-to-save-invalidate-session", "err", err)
		}

		return 0, xerror.Enrich(errordef.ErrOAuth2AccessDenied, "the user failed to authenticate")
	}

	return session.UserID, nil
}

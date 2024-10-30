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
	"github.com/todennus/shared/scopedef"
	"github.com/todennus/shared/tokendef"
	"github.com/todennus/shared/xcontext"
	"github.com/todennus/x/scope"
	"github.com/todennus/x/token"
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

	userRepo               abstraction.UserRepository
	oauth2RefreshTokenRepo abstraction.OAuth2RefreshTokenRepository
	sessionRepo            abstraction.SessionRepository
	oauth2ClientRepo       abstraction.OAuth2ClientRepository
	oauth2CodeRepo         abstraction.OAuth2AuthorizationCodeRepository
	oauth2ConsentRepo      abstraction.OAuth2ConsentRepository
}

func NewOAuth2FlowUsecase(
	tokenEngine token.Engine,
	idpLoginURL string,
	oauth2FlowDomain abstraction.OAuth2FlowDomain,
	oauth2ConsentDomain abstraction.OAuth2ConsentDomain,
	oauth2TokenDomain abstraction.OAuth2TokenDomain,
	oauth2SessionDomain abstraction.OAuth2SessionDomain,
	userRepo abstraction.UserRepository,
	oauth2RefreshTokenRepo abstraction.OAuth2RefreshTokenRepository,
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

		userRepo:               userRepo,
		oauth2RefreshTokenRepo: oauth2RefreshTokenRepo,
		sessionRepo:            sessionRepo,
		oauth2ClientRepo:       oauth2ClientRepo,
		oauth2CodeRepo:         oauth2CodeRepo,
		oauth2ConsentRepo:      oauth2ConsentRepo,
	}
}

func (usecase *OAuth2FlowUsecase) Authorize(
	ctx context.Context,
	req *dto.OAuth2AuthorizeRequest,
) (*dto.OAuth2AuthorizeResponse, error) {
	if _, err := xhttp.ParseURL(req.RedirectURI); err != nil {
		return nil, xerror.Enrich(errordef.ErrRequestInvalid, "invalid redirect uri")
	}

	if scopedef.HasAnyTitle[scopedef.Admin](req.Scope) && req.Scope.Contains(scopedef.OfflineAccess) {
		return nil, xerror.Enrich(errordef.ErrOAuth2ScopeInvalid, "unable request offline-access with admin scope")
	}

	if _, err := usecase.validateClient(ctx, req.ClientID, "", enumdef.CRTNotRequire); err != nil {
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
	if scopedef.HasAnyTitle[scopedef.Admin](req.Scope) && req.Scope.Contains(scopedef.OfflineAccess) {
		return nil, xerror.Enrich(errordef.ErrOAuth2ScopeInvalid, "unable request offline-access with admin scope")
	}

	switch req.GrantType {
	case GrantTypeAuthorizationCode:
		return usecase.exchangeToken(ctx, req)
	case GrantTypePassword:
		return usecase.passwordFlow(ctx, req)
	case GrantTypeRefreshToken:
		return usecase.refreshTokenFlow(ctx, req)
	case GrantTypeClientCredentials:
		return usecase.handleTokenClientCredentialsFlow(ctx, req)
	default:
		return nil, xerror.Enrich(errordef.ErrRequestInvalid, "not support grant type %s", req.GrantType)
	}
}

func (usecase *OAuth2FlowUsecase) handleAuthorizeCodeFlow(
	ctx context.Context,
	req *dto.OAuth2AuthorizeRequest,
) (*dto.OAuth2AuthorizeResponse, error) {
	if err := scopedef.OnlyAllow(req.Scope).HasStandard().HasUser().HasAdmin().Err(); err != nil {
		return nil, xerror.Enrich(errordef.ErrOAuth2ScopeInvalid, err.Error())
	}

	// Authorization Code Flow with PKCE only allows readonly scope.
	if req.CodeChallengeMethod != "" && !scopedef.IsAllReadonly(req.Scope) {
		return nil, xerror.Enrich(errordef.ErrOAuth2ScopeInvalid,
			"only able to request read-only scope when using Authorization Code with PKCE")
	}

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

	if scopedef.HasAnyTitle[scopedef.Admin](req.Scope) {
		user, err := usecase.userRepo.GetByID(ctx, userID)
		if err != nil {
			return nil, errordef.ErrServer.Hide(err, "failed-to-get-user")
		}

		if user.Role != enumdef.UserRoleAdmin {
			return nil, xerror.Enrich(errordef.ErrOAuth2ScopeInvalid,
				"cannot request admin scopes from non-admin user")
		}
	}

	resp, consentScope, err := usecase.validateConsentResult(ctx, userID, req, req.Scope)
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

func (usecase *OAuth2FlowUsecase) exchangeToken(
	ctx context.Context,
	req *dto.OAuth2TokenRequest,
) (*dto.OAuth2TokenResponse, error) {
	// No need validate scope in exchanging token code flow.

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
		if _, err := usecase.validateClient(ctx, req.ClientID, req.ClientSecret, enumdef.CRTRequire); err != nil {
			return nil, err
		}
	} else {
		ok := usecase.oauth2FlowDomain.ValidateCodeChallenge(
			req.CodeVerifier, code.CodeChallenge, code.CodeChallengeMethod)
		if !ok {
			return nil, xerror.Enrich(errordef.ErrOAuth2InvalidGrant, "incorrect code verifier")
		}
	}

	user, err := usecase.userRepo.GetByID(ctx, code.UserID)
	if err != nil {
		return nil, errordef.ErrServer.Hide(err, "failed-to-get-user", "uid", code.UserID)
	}

	return usecase.completeRegularTokenFlow(ctx, "", code.Scope, user)
}

func (usecase *OAuth2FlowUsecase) passwordFlow(
	ctx context.Context,
	req *dto.OAuth2TokenRequest,
) (*dto.OAuth2TokenResponse, error) {
	if err := scopedef.OnlyAllow(req.Scope).HasStandard().HasUser().Err(); err != nil {
		return nil, xerror.Enrich(errordef.ErrOAuth2ScopeInvalid, err.Error())
	}

	// TODO: Only admin client is allowed to use Password Flow.
	if _, err := usecase.validateClient(ctx, req.ClientID, req.ClientSecret, enumdef.CRTRequire); err != nil {
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

func (usecase *OAuth2FlowUsecase) refreshTokenFlow(
	ctx context.Context,
	req *dto.OAuth2TokenRequest,
) (*dto.OAuth2TokenResponse, error) {
	// No need to handle scope in refresh token flow.

	// Check the current refresh token
	cur := &tokendef.OAuth2RefreshToken{}
	if err := usecase.tokenEngine.Validate(ctx, req.RefreshToken, cur); err != nil {
		return nil, xerror.Enrich(errordef.ErrOAuth2InvalidGrant, "refresh token is invalid or expired").
			Hide(err, "failed-to-validate-refresh-token")
	}

	tokenStore, err := usecase.oauth2RefreshTokenRepo.Get(ctx, cur.SnowflakeID())
	if err != nil {
		return nil, xerror.Enrich(errordef.ErrOAuth2InvalidGrant, "refresh token is invalid").
			Hide(err, "failed-to-search-refresh-token")
	}

	if tokenStore.UserID != cur.SnowflakeSub() {
		return nil, errordef.ErrServer.Hide(errors.New("invalid user id in refresh token store"), "invalid-token")
	}

	if _, err = usecase.validateClient(ctx, req.ClientID, req.ClientSecret, enumdef.CRTDependOnType); err != nil {
		return nil, err
	}

	// Get the user to generate access token.
	user, err := usecase.userRepo.GetByID(ctx, tokenStore.UserID)
	if err != nil {
		return nil, errordef.ErrServer.Hide(err, "failed-to-get-user", "uid", tokenStore.UserID)
	}

	// Generate tokens.
	accessToken := usecase.oauth2TokenDomain.NewUserAccessToken(cur.Audience, tokenStore.Scope, user)
	next := usecase.oauth2TokenDomain.NextRefreshToken(dto.OAuth2RefreshTokenToDomain(cur))

	// Serialize both tokens.
	accessTokenString, refreshTokenString, err := usecase.serializeAccessAndRefreshTokens(ctx, accessToken, next)
	if err != nil {
		return nil, err
	}

	// Store the seq number again.
	newStore := usecase.oauth2TokenDomain.NewRefreshTokenStore(next, accessToken)
	if err := usecase.oauth2RefreshTokenRepo.Update(ctx, newStore); err != nil {
		if errors.Is(err, errordef.ErrNotFound) {
			if err = usecase.oauth2RefreshTokenRepo.Delete(ctx, cur.SnowflakeID()); err != nil {
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
		Scope:        tokenStore.Scope,
	}, nil
}

func (usecase *OAuth2FlowUsecase) handleTokenClientCredentialsFlow(
	ctx context.Context,
	req *dto.OAuth2TokenRequest,
) (*dto.OAuth2TokenResponse, error) {
	if err := scopedef.OnlyAllow(req.Scope).HasAdmin().HasApp().Err(); err != nil {
		return nil, xerror.Enrich(errordef.ErrOAuth2ScopeInvalid, err.Error())
	}

	client, err := usecase.validateClient(ctx, req.ClientID, req.ClientSecret, enumdef.CRTRequire)
	if err != nil {
		return nil, err
	}

	if !client.IsAdmin && scopedef.HasAnyTitle[scopedef.Admin](req.Scope) {
		return nil, xerror.Enrich(errordef.ErrOAuth2ScopeInvalid,
			"unable to request admin scope if client is not admin")
	}

	accessToken := usecase.oauth2TokenDomain.NewClientAccessToken("", req.Scope, client)
	accessTokenString, err := usecase.tokenEngine.Generate(ctx, dto.OAuth2AccessTokenFromDomain(accessToken))
	if err != nil {
		return nil, errordef.ErrServer.Hide(err, "failed-to-generate-access-token")
	}

	return &dto.OAuth2TokenResponse{
		AccessToken: accessTokenString,
		TokenType:   usecase.tokenEngine.Type(),
		ExpiresIn:   usecase.getExpiresIn(accessToken.Metadata),
		Scope:       req.Scope,
	}, nil
}

func (usecase *OAuth2FlowUsecase) serializeAccessAndRefreshTokens(
	ctx context.Context,
	accessToken *domain.OAuth2AccessToken,
	refreshToken *domain.OAuth2RefreshToken,
) (string, string, error) {
	var err error
	accessTokenString, err := usecase.tokenEngine.Generate(ctx, dto.OAuth2AccessTokenFromDomain(accessToken))
	if err != nil {
		return "", "", errordef.ErrServer.Hide(err, "failed-to-generate-access-token")
	}

	var refreshTokenString string
	if refreshToken != nil {
		refreshTokenString, err = usecase.tokenEngine.Generate(ctx, dto.OAuth2RefreshTokenFromDomain(refreshToken))
		if err != nil {
			return "", "", errordef.ErrServer.Hide(err, "failed-to-generate-refresh-token")
		}
	}

	return accessTokenString, refreshTokenString, nil
}

func (usecase *OAuth2FlowUsecase) completeRegularTokenFlow(
	ctx context.Context,
	aud string,
	scope scope.Scopes,
	user *domain.User,
) (*dto.OAuth2TokenResponse, error) {
	accessToken := usecase.oauth2TokenDomain.NewUserAccessToken(aud, scope, user)

	var refreshToken *domain.OAuth2RefreshToken
	if scope.Contains(scopedef.OfflineAccess) {
		refreshToken = usecase.oauth2TokenDomain.NewRefreshToken(aud, user.ID)
	}

	// Serialize both tokens.
	accessTokenString, refreshTokenString, err := usecase.serializeAccessAndRefreshTokens(
		ctx, accessToken, refreshToken)
	if err != nil {
		return nil, err
	}

	// Store refresh token information.
	if refreshToken != nil {
		store := usecase.oauth2TokenDomain.NewRefreshTokenStore(refreshToken, accessToken)
		if err = usecase.oauth2RefreshTokenRepo.Create(ctx, store); err != nil {
			return nil, errordef.ErrServer.Hide(err, "failed-to-save-refresh-token")
		}
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
	userID snowflake.ID,
	req *dto.OAuth2AuthorizeRequest,
	requestedScope scope.Scopes,
) (*dto.OAuth2AuthorizeResponse, scope.Scopes, error) {
	logger := xcontext.Logger(ctx).With("cid", req.ClientID, "uid", userID)

	result, err := usecase.oauth2ConsentRepo.LoadResult(ctx, userID, req.ClientID)
	if err == nil {
		if err := usecase.oauth2ConsentRepo.DeleteResult(ctx, userID, req.ClientID); err != nil {
			logger.Warn("failed-to-delete-failure-consent-result", "err", err)
		}

		if result.ExpiresAt.Before(time.Now()) {
			return usecase.redirectToConsentPage(ctx, req, requestedScope)
		}

		if result.Accepted {
			if !requestedScope.Contains(result.Scope...) {
				return nil, nil, xerror.Enrich(errordef.ErrOAuth2ScopeInvalid,
					"user choose more scopes than the request from client")
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

	consent, err := usecase.oauth2ConsentRepo.Get(ctx, userID, req.ClientID)
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
	requirement enumdef.OAuth2ClientConfidentialRequirement,
) (*domain.OAuth2Client, error) {
	client, err := usecase.oauth2ClientRepo.Validate(ctx, clientID, clientSecret, requirement)
	if err != nil {
		if errors.Is(err, errordef.ErrRequestInvalid) {
			return nil, xerror.Enrich(errordef.ErrOAuth2ClientInvalid, "not provided client id")
		}

		if errors.Is(err, errordef.ErrNotFound) {
			return nil, xerror.Enrich(errordef.ErrOAuth2ClientInvalid, "not found client")
		}

		if errors.Is(err, errordef.ErrOAuth2ClientInvalid) {
			return nil, xerror.Enrich(errordef.ErrOAuth2ClientInvalid, "unsupported client type")
		}

		if errors.Is(err, errordef.ErrCredentialsInvalid) {
			return nil, xerror.Enrich(errordef.ErrOAuth2ClientInvalid, "client credentials is incorrect")
		}

		return nil, errordef.ErrServer.Hide(err, "failed-to-validate-client")
	}

	return client, nil
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

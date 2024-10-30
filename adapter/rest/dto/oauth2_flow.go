package dto

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/todennus/oauth2-service/usecase/dto"
	"github.com/todennus/shared/errordef"
	"github.com/todennus/shared/response"
	"github.com/todennus/shared/scopedef"
	"github.com/todennus/x/xerror"
	"github.com/todennus/x/xhttp"
	"github.com/xybor-x/snowflake"
)

type OAuth2TokenRequest struct {
	GrantType string `form:"grant_type"`

	ClientID     int64  `form:"client_id"`
	ClientSecret string `form:"client_secret"`

	// Authorization Code Flow
	Code         string `form:"code"`
	RedirectURI  string `form:"redirect_uri"`
	CodeVerifier string `form:"code_verifier"` // with PKCE

	// Resource Owner Password Credentials Flow
	Username string `form:"username"`
	Password string `form:"password"`
	Scope    string `form:"scope"`

	// Refresh Token Flow
	RefreshToken string `form:"refresh_token"`
}

func (req OAuth2TokenRequest) To() *dto.OAuth2TokenRequest {
	return &dto.OAuth2TokenRequest{
		GrantType: req.GrantType,

		ClientID:     snowflake.ID(req.ClientID),
		ClientSecret: req.ClientSecret,

		Code:         req.Code,
		RedirectURI:  req.RedirectURI,
		CodeVerifier: req.CodeVerifier,

		Username: req.Username,
		Password: req.Password,
		Scope:    scopedef.Engine.ParseAnyScopes(req.Scope),

		RefreshToken: req.RefreshToken,
	}
}

type OAuth2TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

func NewOAuth2TokenResponse(resp *dto.OAuth2TokenResponse) *OAuth2TokenResponse {
	if resp == nil {
		return nil
	}

	return &OAuth2TokenResponse{
		AccessToken:  resp.AccessToken,
		TokenType:    resp.TokenType,
		ExpiresIn:    resp.ExpiresIn,
		RefreshToken: resp.RefreshToken,
		Scope:        resp.Scope.String(),
	}
}

type OAuth2AuthorizeRequest struct {
	ResponseType string `query:"response_type"`
	ClientID     int64  `query:"client_id"`
	RedirectURI  string `query:"redirect_uri"`
	Scope        string `query:"scope"`
	State        string `query:"state"`

	// For PKCE
	CodeChallenge       string `query:"code_challenge"`
	CodeChallengeMethod string `query:"code_challenge_method"`
}

func (req OAuth2AuthorizeRequest) To() *dto.OAuth2AuthorizeRequest {
	return &dto.OAuth2AuthorizeRequest{
		ResponseType:        req.ResponseType,
		ClientID:            snowflake.ID(req.ClientID),
		RedirectURI:         req.RedirectURI,
		Scope:               scopedef.Engine.ParseAnyScopes(req.Scope),
		State:               req.State,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
	}
}

func NewOAuth2AuthorizeRedirectURI(
	req *OAuth2AuthorizeRequest,
	resp *dto.OAuth2AuthorizeResponse,
) (string, error) {
	if resp.IdpURL != "" {
		u, err := url.Parse(resp.IdpURL)
		if err != nil {
			return "", errordef.ErrServer.Hide(err, "invalid-idp-url", "url", resp.IdpURL)
		}

		q := u.Query()
		q.Set("authorization_id", resp.AuthorizationID)
		u.RawQuery = q.Encode()

		return u.String(), nil
	}

	if resp.NeedConsent {
		return fmt.Sprintf("/oauth2/consent?authorization_id=%s", resp.AuthorizationID), nil
	}

	u, err := url.Parse(req.RedirectURI)
	if err != nil {
		return "", xerror.Enrich(errordef.ErrRequestInvalid, "invalid redirect uri").
			Hide(err, "invalid-redirect-url", "url", req.RedirectURI)
	}

	q := u.Query()

	if req.State != "" {
		q.Set("state", req.State)
	}

	if resp.Code != "" {
		q.Set("code", resp.Code)
	} else {
		if resp.AccessToken != "" || resp.ExpiresIn == 0 || resp.TokenType == "" {
			return "", errors.New("expected access_token, token_type, and expires_in if resp type is token")
		}

		q.Set("access_token", resp.AccessToken)
		q.Set("token_type", resp.TokenType)
		q.Set("expires_in", strconv.FormatInt(int64(resp.ExpiresIn), 10))
	}

	u.RawQuery = q.Encode()

	return u.String(), nil
}

func NewOAuth2AuthorizeRedirectURIWithError(
	ctx context.Context,
	req *OAuth2AuthorizeRequest,
	err error,
) (string, error) {
	u, uerr := xhttp.ParseURL(req.RedirectURI)
	if uerr != nil {
		return "", xerror.Enrich(errordef.ErrRequestInvalid, "invalid redirect uri").
			Hide(err, "invalid-redirect-uri", "uri", req.RedirectURI)
	}

	if timeoutErr := context.Cause(ctx); timeoutErr != nil && errors.Is(timeoutErr, errordef.ErrServerTimeout) {
		err = errordef.ErrServerTimeout.Hide(err, "timeout")
	}

	q := u.Query()
	response.SetQuery(ctx, q, err)
	if req.State != "" {
		q.Set("state", req.State)
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

type OAuth2AuthenticationCallbackRequest struct {
	IdPSecret       string `json:"idp_secret" example:"Sde3kl..."`
	AuthorizationID string `json:"authorization_id" example:"djG4l..."`
	Success         bool   `json:"success" example:"true"`
	UserID          string `json:"user_id" example:"329780019283901"`
	Username        string `json:"username" example:"huykingsofm"`
	Error           string `json:"error" example:""`
}

func (req OAuth2AuthenticationCallbackRequest) To() (*dto.OAuth2AuthenticationCallbackRequest, error) {
	uid, err := snowflake.ParseString(req.UserID)
	if err != nil {
		return nil, xerror.Enrich(errordef.ErrRequestInvalid, "invalid user id").
			Hide(err, "invalid-user-id", "uid", req.UserID)
	}

	return &dto.OAuth2AuthenticationCallbackRequest{
		Secret:          req.IdPSecret,
		Success:         req.Success,
		AuthorizationID: req.AuthorizationID,
		UserID:          uid,
		Username:        req.Username,
		Error:           req.Error,
	}, nil
}

type OAuth2AuthenticationCallbackResponse struct {
	AuthenticationID string `json:"authentication_id" example:"hlqWe..."`
}

func NewOAuth2AuthenticationCallbackResponse(resp *dto.OAuth2AuthenticationCallbackResponse) *OAuth2AuthenticationCallbackResponse {
	if resp == nil {
		return nil
	}

	return &OAuth2AuthenticationCallbackResponse{
		AuthenticationID: resp.AuthenticationID,
	}
}

type OAuth2SessionUpdateRequest struct {
	AuthenticationID string `query:"authentication_id"`
}

func (req OAuth2SessionUpdateRequest) To() *dto.OAuth2SessionUpdateRequest {
	return &dto.OAuth2SessionUpdateRequest{
		AuthenticationID: req.AuthenticationID,
	}
}

func NewOAuth2SessionUpdateRedirectURI(resp *dto.OAuth2SessionUpdateResponse) string {
	return restoreOAuth2AuthorizeURL((*dto.OAuth2AuthorizeRequest)(resp))
}

type OAuth2GetConsentPageRequest struct {
	AuthorizationID string `query:"authorization_id"`
}

func (req OAuth2GetConsentPageRequest) To() *dto.OAuth2GetConsentRequest {
	return &dto.OAuth2GetConsentRequest{
		AuthorizationID: req.AuthorizationID,
	}
}

type ConsentPageScope struct {
	Description string
	IsAdmin     bool
	Key         string
}

type OAuth2GetConsentPageResponse struct {
	ClientName string
	ClientID   int64

	Scopes []ConsentPageScope
}

func NewOAuth2GetConsentPageResponse(resp *dto.OAuth2GetConsentResponse) *OAuth2GetConsentPageResponse {
	scopes := []ConsentPageScope{}
	for i := range resp.Scopes {
		scope, ok := resp.Scopes[i].(scopedef.DescriptiveScope)
		if !ok {
			continue
		}

		scopes = append(scopes, ConsentPageScope{
			Description: scope.Description(),
			IsAdmin:     scopedef.IsTitle[scopedef.Admin](scope),
			Key:         scope.Scope(),
		})
	}

	return &OAuth2GetConsentPageResponse{
		ClientName: resp.Client.Name,
		ClientID:   resp.Client.ClientID.Int64(),
		Scopes:     scopes,
	}
}

type OAuth2UpdateConsentRequest struct {
	AuthorizationID string `query:"authorization_id"`
	Consent         string `form:"consent"`
}

func (req OAuth2UpdateConsentRequest) To() *dto.OAuth2UpdateConsentRequest {
	accept := false
	if strings.ToLower(req.Consent) == "accepted" {
		accept = true
	}

	return &dto.OAuth2UpdateConsentRequest{
		Accept:          accept,
		AuthorizationID: req.AuthorizationID,
	}
}

func NewOAuth2ConsentUpdateRedirectURI(resp *dto.OAUth2UpdateConsentResponse) string {
	return restoreOAuth2AuthorizeURL((*dto.OAuth2AuthorizeRequest)(resp))
}

func restoreOAuth2AuthorizeURL(request *dto.OAuth2AuthorizeRequest) string {
	if request == nil {
		return ""
	}

	q := url.Values{}
	q.Set("response_type", request.ResponseType)
	q.Set("client_id", request.ClientID.String())
	q.Set("redirect_uri", request.RedirectURI)
	q.Set("scope", request.Scope.String())

	if request.State != "" {
		q.Set("state", request.State)
	}

	if request.CodeChallenge != "" {
		q.Set("code_challenge", request.CodeChallenge)
	}

	if request.CodeChallengeMethod != "" {
		q.Set("code_challenge_method", request.CodeChallengeMethod)
	}

	return fmt.Sprintf("/oauth2/authorize?%s", q.Encode())
}

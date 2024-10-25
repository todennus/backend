package abstraction

import (
	"github.com/todennus/oauth2-service/domain"
	"github.com/todennus/x/scope"
	"github.com/xybor-x/snowflake"
)

type OAuth2FlowDomain interface {
	NewAuthorizationCode(
		userID, clientID snowflake.ID,
		scope scope.Scopes,
		codeChallenge, codeChallengeMethod string,
	) *domain.OAuth2AuthorizationCode
	NewAuthorizationStore(
		respType string,
		clientID snowflake.ID,
		scope scope.Scopes,
		redirectURI, state, codeChallenge, codeChallengeMethod string,
	) *domain.OAuth2AuthorizationStore
	NewAuthenticationResultSuccess(authID string, userID snowflake.ID, username string) *domain.OAuth2AuthenticationResult
	NewAuthenticationResultFailure(authID string, err string) *domain.OAuth2AuthenticationResult

	NewAccessToken(aud string, scope scope.Scopes, user *domain.User) *domain.OAuth2AccessToken
	NewRefreshToken(aud string, scope scope.Scopes, userID snowflake.ID) *domain.OAuth2RefreshToken
	NextRefreshToken(current *domain.OAuth2RefreshToken) *domain.OAuth2RefreshToken
	NewIDToken(aud string, user *domain.User) *domain.OAuth2IDToken

	ValidateCodeChallenge(verifier, challenge, method string) bool
	ValidateRequestedScope(requestedScope scope.Scopes, client *domain.OAuth2Client) error

	NewSession(userID snowflake.ID) *domain.Session
	InvalidateSession(state domain.SessionState) *domain.Session
}

type OAuth2ClientDomain interface {
	NewClient(ownerID snowflake.ID, name string, isConfidential bool) (*domain.OAuth2Client, string, error)
	ValidateClient(
		client *domain.OAuth2Client,
		clientID snowflake.ID,
		clientSecret string,
		confidentialRequirement domain.ConfidentialRequirementType,
	) error
}

type OAuth2ConsentDomain interface {
	NewConsentDeniedResult(userID, clientID snowflake.ID) *domain.OAuth2ConsentResult
	NewConsentAcceptedResult(userID, clientID snowflake.ID, userScope scope.Scopes) *domain.OAuth2ConsentResult
	NewConsent(userID, clientID snowflake.ID, requestedScope scope.Scopes) *domain.OAuth2Consent
	ValidateConsent(consent *domain.OAuth2Consent, requestScope scope.Scopes) error
}

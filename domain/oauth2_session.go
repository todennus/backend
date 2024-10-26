package domain

import (
	"time"

	"github.com/todennus/x/scope"
	"github.com/todennus/x/xcrypto"
	"github.com/xybor-x/snowflake"
)

type SessionState int

const (
	SessionStateUnauthenticated = iota
	SessionStateAuthenticated
	SessionStateFailedAuthentication
)

const (
	CodeChallengeMethodPlain = "plain"
	CodeChallengeMethodS256  = "S256"
)

type Session struct {
	State     SessionState
	UserID    snowflake.ID
	ExpiresAt time.Time
}

type OAuth2AuthorizationStore struct {
	ID                  string
	IsOpen              bool
	ResponseType        string
	ClientID            snowflake.ID
	RedirectURI         string
	Scope               scope.Scopes
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
}

type OAuth2AuthenticationResult struct {
	ID              string
	AuthorizationID string
	Ok              bool
	Error           string
	UserID          snowflake.ID
	Username        string
	ExpiresAt       time.Time
}

type OAuth2SessionDomain struct {
	AuthenticationCallbackExpiration time.Duration
	SessionUpdateExpiration          time.Duration
	SessionExpiration                time.Duration
}

func NewOAuth2SessionDomain(
	authenticationCallbackExpiration time.Duration,
	sessionUpdateExpiration time.Duration,
	sessionExpiration time.Duration,
) *OAuth2SessionDomain {
	return &OAuth2SessionDomain{
		AuthenticationCallbackExpiration: authenticationCallbackExpiration,
		SessionUpdateExpiration:          sessionUpdateExpiration,
		SessionExpiration:                sessionExpiration,
	}
}

func (domain *OAuth2SessionDomain) NewAuthorizationStore(
	open bool,
	respType string,
	clientID snowflake.ID,
	scope scope.Scopes,
	redirectURI, state, codeChallenge, codeChallengeMethod string,
) *OAuth2AuthorizationStore {
	return &OAuth2AuthorizationStore{
		ID:                  xcrypto.RandString(32),
		ResponseType:        respType,
		IsOpen:              open,
		Scope:               scope,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		State:               state,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		ExpiresAt:           time.Now().Add(domain.AuthenticationCallbackExpiration),
	}
}

func (domain *OAuth2SessionDomain) NewAuthenticationResultSuccess(
	authID string,
	userID snowflake.ID,
	username string,
) *OAuth2AuthenticationResult {
	return &OAuth2AuthenticationResult{
		ID:              xcrypto.RandString(32),
		Ok:              true,
		AuthorizationID: authID,
		UserID:          userID,
		Username:        username,
		ExpiresAt:       time.Now().Add(domain.SessionUpdateExpiration),
	}
}

func (domain *OAuth2SessionDomain) NewAuthenticationResultFailure(authID string, err string) *OAuth2AuthenticationResult {
	return &OAuth2AuthenticationResult{
		ID:              xcrypto.RandString(32),
		Ok:              false,
		AuthorizationID: authID,
		Error:           err,
		ExpiresAt:       time.Now().Add(domain.SessionUpdateExpiration),
	}
}

func (domain *OAuth2SessionDomain) NewSession(userID snowflake.ID) *Session {
	return &Session{
		State:     SessionStateAuthenticated,
		UserID:    userID,
		ExpiresAt: time.Now().Add(domain.SessionExpiration),
	}
}

func (domain *OAuth2SessionDomain) InvalidateSession(state SessionState) *Session {
	if state != SessionStateFailedAuthentication && state != SessionStateUnauthenticated {
		panic("invalid call")
	}

	return &Session{State: state, ExpiresAt: time.Now().Add(domain.SessionExpiration)}
}

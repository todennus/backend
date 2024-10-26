package domain

import (
	"crypto/sha256"
	"encoding/base64"
	"time"

	"github.com/todennus/x/scope"
	"github.com/todennus/x/xcrypto"
	"github.com/xybor-x/snowflake"
)

type OAuth2AuthorizationCode struct {
	Code                string
	UserID              snowflake.ID
	ClientID            snowflake.ID
	Scope               scope.Scopes
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
}

type OAuth2FlowDomain struct {
	AuthorizationCodeFlowExpiration time.Duration
}

func NewOAuth2FlowDomain(
	authorizationCodeFlowExpiration time.Duration,
) *OAuth2FlowDomain {
	return &OAuth2FlowDomain{
		AuthorizationCodeFlowExpiration: authorizationCodeFlowExpiration,
	}
}

func (domain *OAuth2FlowDomain) NewAuthorizationCode(
	userID, clientID snowflake.ID,
	scope scope.Scopes,
	codeChallenge, codeChallengeMethod string,
) *OAuth2AuthorizationCode {
	return &OAuth2AuthorizationCode{
		Code:                xcrypto.RandString(32),
		Scope:               scope,
		UserID:              userID,
		ClientID:            clientID,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		ExpiresAt:           time.Now().Add(domain.AuthorizationCodeFlowExpiration),
	}
}

func (domain *OAuth2FlowDomain) ValidateCodeChallenge(verifier, challenge, method string) bool {
	switch method {
	case CodeChallengeMethodPlain:
		return verifier == challenge
	default: // CodeChallengeMethodS256
		hash := sha256.Sum256([]byte(verifier))
		encoded := base64.RawURLEncoding.EncodeToString(hash[:])
		return encoded == challenge
	}
}

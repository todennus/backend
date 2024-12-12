package domain

import (
	"time"

	"github.com/todennus/shared/enumdef"
	"github.com/todennus/x/scope"
	"github.com/xybor-x/snowflake"
)

type OAuth2TokenMedata struct {
	ID        snowflake.ID
	Issuer    string
	Audience  string
	Subject   snowflake.ID
	ExpiresAt int
	NotBefore int
}

type OAuth2AccessToken struct {
	Metadata *OAuth2TokenMedata
	Scope    scope.Scopes
	Role     enumdef.UserRole
}

type OAuth2RefreshToken struct {
	Metadata       *OAuth2TokenMedata
	SequenceNumber int
}

type OAuth2IDToken struct {
	Metadata *OAuth2TokenMedata
	User     *User
}

type OAuth2RefreshTokenStorage struct {
	ID             snowflake.ID
	AccessTokenID  snowflake.ID // Used for search and analystics
	UserID         snowflake.ID // Used for search and analystics
	Scope          scope.Scopes
	SequenceNumber int
	ExpiresAt      time.Time
}

type OAuth2TokenDomain struct {
	Snowflake              *snowflake.Node
	Issuer                 string
	AccessTokenExpiration  time.Duration
	RefreshTokenExpiration time.Duration
	IDTokenExpiration      time.Duration
	AdminTokenExpiration   time.Duration
}

func NewOAuth2TokenDomain(
	snowflake *snowflake.Node,
	issuer string,
	accessTokenExpiration time.Duration,
	refreshTokenExpiration time.Duration,
	idTokenExpiration time.Duration,
) *OAuth2TokenDomain {
	return &OAuth2TokenDomain{
		Snowflake: snowflake,
		Issuer:    issuer,

		AccessTokenExpiration:  accessTokenExpiration,
		RefreshTokenExpiration: refreshTokenExpiration,
		IDTokenExpiration:      idTokenExpiration,
	}
}

func (domain *OAuth2TokenDomain) NewUserAccessToken(aud string, scope scope.Scopes, user *User) *OAuth2AccessToken {
	return &OAuth2AccessToken{
		Metadata: domain.createMedata(aud, user.ID, domain.AccessTokenExpiration),
		Scope:    scope,
		Role:     user.Role,
	}
}

func (domain *OAuth2TokenDomain) NewClientAccessToken(aud string, scope scope.Scopes, client *OAuth2Client) *OAuth2AccessToken {
	return &OAuth2AccessToken{
		Metadata: domain.createMedata(aud, client.ID, domain.AccessTokenExpiration),
		Scope:    scope,
	}
}

func (domain *OAuth2TokenDomain) NewRefreshToken(aud string, userID snowflake.ID) *OAuth2RefreshToken {
	return &OAuth2RefreshToken{
		Metadata:       domain.createMedata(aud, userID, domain.RefreshTokenExpiration),
		SequenceNumber: 0,
	}
}

func (domain *OAuth2TokenDomain) NextRefreshToken(current *OAuth2RefreshToken) *OAuth2RefreshToken {
	next := domain.NewRefreshToken(current.Metadata.Audience, current.Metadata.Subject)
	next.Metadata.ID = current.Metadata.ID
	next.SequenceNumber = current.SequenceNumber + 1
	return next
}

func (domain *OAuth2TokenDomain) NewRefreshTokenStore(
	refreshToken *OAuth2RefreshToken,
	accessToken *OAuth2AccessToken,
) *OAuth2RefreshTokenStorage {
	return &OAuth2RefreshTokenStorage{
		ID:             refreshToken.Metadata.ID,
		AccessTokenID:  accessToken.Metadata.ID,
		UserID:         refreshToken.Metadata.Subject,
		Scope:          accessToken.Scope,
		SequenceNumber: refreshToken.SequenceNumber,
		ExpiresAt:      time.Unix(int64(refreshToken.Metadata.ExpiresAt), 0),
	}
}

func (domain *OAuth2TokenDomain) NewIDToken(aud string, user *User) *OAuth2IDToken {
	return &OAuth2IDToken{
		Metadata: domain.createMedata(aud, user.ID, domain.IDTokenExpiration),
		User:     user,
	}
}

func (domain *OAuth2TokenDomain) createMedata(aud string, sub snowflake.ID, expiration time.Duration) *OAuth2TokenMedata {
	id := domain.Snowflake.Generate()

	return &OAuth2TokenMedata{
		ID:        id,
		Issuer:    domain.Issuer,
		Audience:  aud,
		Subject:   sub,
		ExpiresAt: int(time.UnixMilli(id.Time()).Add(expiration).Unix()),
		NotBefore: int(time.UnixMilli(id.Time()).Unix()),
	}
}

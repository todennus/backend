package abstraction

import (
	"context"

	"github.com/todennus/oauth2-service/domain"
	"github.com/todennus/shared/enumdef"
)

type UserRepository interface {
	GetByID(ctx context.Context, userID int64) (*domain.User, error)
	Validate(ctx context.Context, username string, password string) (*domain.User, error)
}

type RefreshTokenRepository interface {
	Create(ctx context.Context, refreshTokenID, accessTokenID int64, seq int) error
	UpdateByRefreshTokenID(ctx context.Context, refreshTokenID, accessTokenId int64, expectedCurSeq int) error
	DeleteByRefreshTokenID(ctx context.Context, refreshTokenID int64) error
}

type OAuth2ClientRepository interface {
	GetByID(ctx context.Context, clientID int64) (*domain.OAuth2Client, error)
	Validate(
		ctx context.Context,
		clientID int64,
		clientSecret string,
		require enumdef.ConfidentialRequirementType,
		requestedScope string,
	) error
}

type SessionRepository interface {
	Save(ctx context.Context, session *domain.Session) error
	Load(ctx context.Context) (*domain.Session, error)
}

type OAuth2AuthorizationCodeRepository interface {
	SaveAuthorizationCode(ctx context.Context, info *domain.OAuth2AuthorizationCode) error
	LoadAuthorizationCode(ctx context.Context, code string) (*domain.OAuth2AuthorizationCode, error)
	DeleteAuthorizationCode(ctx context.Context, code string) error

	SaveAuthorizationStore(ctx context.Context, store *domain.OAuth2AuthorizationStore) error
	LoadAuthorizationStore(ctx context.Context, id string) (*domain.OAuth2AuthorizationStore, error)
	DeleteAuthorizationStore(ctx context.Context, id string) error

	SaveAuthenticationResult(ctx context.Context, result *domain.OAuth2AuthenticationResult) error
	LoadAuthenticationResult(ctx context.Context, id string) (*domain.OAuth2AuthenticationResult, error)
	DeleteAuthenticationResult(ctx context.Context, id string) error
}

type OAuth2ConsentRepository interface {
	SaveResult(ctx context.Context, result *domain.OAuth2ConsentResult) error
	LoadResult(ctx context.Context, userID, clientID int64) (*domain.OAuth2ConsentResult, error)
	DeleteResult(ctx context.Context, userID, clientID int64) error

	Upsert(ctx context.Context, consent *domain.OAuth2Consent) error
	Get(ctx context.Context, userID, clientID int64) (*domain.OAuth2Consent, error)
}

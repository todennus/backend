package abstraction

import (
	"context"

	"github.com/todennus/oauth2-service/domain"
	"github.com/todennus/shared/enumdef"
	"github.com/xybor-x/snowflake"
)

type UserRepository interface {
	GetByID(ctx context.Context, userID snowflake.ID) (*domain.User, error)
	Validate(ctx context.Context, username string, password string) (*domain.User, error)
}

type OAuth2RefreshTokenRepository interface {
	Get(ctx context.Context, id snowflake.ID) (*domain.OAuth2RefreshTokenStorage, error)
	Create(ctx context.Context, token *domain.OAuth2RefreshTokenStorage) error
	Update(ctx context.Context, token *domain.OAuth2RefreshTokenStorage) error
	Delete(ctx context.Context, refreshTokenID snowflake.ID) error
}

type OAuth2ClientRepository interface {
	GetByID(ctx context.Context, clientID snowflake.ID) (*domain.OAuth2Client, error)
	Validate(
		ctx context.Context,
		clientID snowflake.ID,
		clientSecret string,
		require enumdef.OAuth2ClientConfidentialRequirement,
	) (*domain.OAuth2Client, error)
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
	LoadResult(ctx context.Context, userID, clientID snowflake.ID) (*domain.OAuth2ConsentResult, error)
	DeleteResult(ctx context.Context, userID, clientID snowflake.ID) error

	Upsert(ctx context.Context, consent *domain.OAuth2Consent) error
	Get(ctx context.Context, userID, clientID snowflake.ID) (*domain.OAuth2Consent, error)
}

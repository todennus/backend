package domain

import (
	"errors"
	"fmt"
	"time"

	"github.com/todennus/shared/scopedef"
	"github.com/todennus/x/scope"
	"github.com/todennus/x/xcrypto"
	"github.com/todennus/x/xstring"
	"github.com/xybor-x/snowflake"
)

const (
	MaximumClientNameLength int = 64
	MinimumClientNameLength int = 3
)

type ConfidentialRequirementType int

const (
	RequireConfidential ConfidentialRequirementType = iota
	NotRequireConfidential
	DependOnClientConfidential
)

type OAuth2Client struct {
	ID             snowflake.ID
	OwnerUserID    snowflake.ID
	Name           string
	HashedSecret   string
	IsConfidential bool
	AllowedScope   scope.Scopes
	UpdatedAt      time.Time
}

type OAuth2ClientDomain struct {
	Snowflake          *snowflake.Node
	ClientSecretLength int
}

func NewOAuth2ClientDomain(
	snowflake *snowflake.Node,
	clientSecretLength int,
) (*OAuth2ClientDomain, error) {
	return &OAuth2ClientDomain{
		Snowflake:          snowflake,
		ClientSecretLength: clientSecretLength,
	}, nil
}

func (domain *OAuth2ClientDomain) NewClient(ownerID snowflake.ID, name string, isConfidential bool) (*OAuth2Client, string, error) {
	err := domain.validateClientName(name)
	if err != nil {
		return nil, "", err
	}

	secret := ""
	allowedScope := scopedef.Engine.New(scopedef.Actions.Read, scopedef.Resources).AsScopes()
	hashedSecret := []byte{}
	if isConfidential {
		secret = xcrypto.RandString(domain.ClientSecretLength)
		hashedSecret, err = HashPassword(secret)
		if err != nil {
			return nil, "", err
		}

		allowedScope = scopedef.Engine.New(scopedef.Actions, scopedef.Resources).AsScopes()
	}

	return &OAuth2Client{
		ID:             domain.Snowflake.Generate(),
		Name:           name,
		OwnerUserID:    ownerID,
		IsConfidential: isConfidential,
		AllowedScope:   allowedScope,
		HashedSecret:   string(hashedSecret),
	}, secret, nil
}

func (domain *OAuth2ClientDomain) ValidateClient(
	client *OAuth2Client,
	clientID snowflake.ID,
	clientSecret string,
	confidentialRequirement ConfidentialRequirementType,
) error {
	if client.ID != clientID {
		return errors.New("mismatched client id")
	}

	switch confidentialRequirement {
	case RequireConfidential:
		if !client.IsConfidential {
			return fmt.Errorf("%w: require a confidential client", ErrClientInvalid)
		}

		err := ValidatePassword(client.HashedSecret, clientSecret)
		if err != nil {
			return err
		}

	case DependOnClientConfidential:
		if client.IsConfidential {
			err := ValidatePassword(client.HashedSecret, clientSecret)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (domain *OAuth2ClientDomain) validateClientName(clientName string) error {
	if len(clientName) > MaximumClientNameLength {
		return fmt.Errorf("%w: require at most %d characters", ErrClientNameInvalid, MaximumClientNameLength)
	}

	if len(clientName) < MinimumClientNameLength {
		return fmt.Errorf("%w: require at least %d characters", ErrClientNameInvalid, MinimumClientNameLength)
	}

	for _, c := range clientName {
		if !xstring.IsNumber(c) && !xstring.IsLetter(c) && !xstring.IsUnderscore(c) && !xstring.IsSpace(c) {
			return fmt.Errorf("%w: got an invalid character %c", ErrClientNameInvalid, c)
		}
	}

	return nil
}

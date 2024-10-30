package model

import (
	"time"

	"github.com/todennus/oauth2-service/domain"
	"github.com/todennus/shared/scopedef"
	"github.com/xybor-x/snowflake"
)

type OAuth2RefreshTokenModel struct {
	ID            int64     `gorm:"id;primaryKey"`
	AccessTokenID int64     `gorm:"access_token_id"`
	UserID        int64     `gorm:"user_id"`
	Seq           int       `gorm:"seq"`
	Scope         string    `gorm:"scope"`
	UpdatedAt     time.Time `gorm:"updated_at"`
	ExpiresAt     time.Time `gorm:"expires_at"`
}

func (OAuth2RefreshTokenModel) TableName() string {
	return "oauth2_refresh_tokens"
}

func NewOAuth2RefreshTokenModel(store *domain.OAuth2RefreshTokenStorage) *OAuth2RefreshTokenModel {
	return &OAuth2RefreshTokenModel{
		ID:            store.ID.Int64(),
		AccessTokenID: store.AccessTokenID.Int64(),
		UserID:        store.UserID.Int64(),
		Seq:           store.SequenceNumber,
		Scope:         store.Scope.String(),
		ExpiresAt:     store.ExpiresAt,
	}
}

func (store *OAuth2RefreshTokenModel) To() *domain.OAuth2RefreshTokenStorage {
	return &domain.OAuth2RefreshTokenStorage{
		ID:             snowflake.ID(store.ID),
		AccessTokenID:  snowflake.ID(store.AccessTokenID),
		UserID:         snowflake.ID(store.UserID),
		SequenceNumber: store.Seq,
		Scope:          scopedef.Engine.ParseAnyScopes(store.Scope),
		ExpiresAt:      store.ExpiresAt,
	}
}

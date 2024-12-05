package gorm

import (
	"context"

	"github.com/todennus/oauth2-service/domain"
	"github.com/todennus/oauth2-service/infras/database/model"
	"github.com/todennus/shared/errordef"
	"github.com/todennus/shared/xcontext"
	"github.com/xybor-x/snowflake"
	"gorm.io/gorm"
)

type OAuth2RefreshTokenRepository struct {
	db *gorm.DB
}

func NewOAuth2RefreshTokenRepository(db *gorm.DB) *OAuth2RefreshTokenRepository {
	return &OAuth2RefreshTokenRepository{db: db}
}

func (repo *OAuth2RefreshTokenRepository) Get(
	ctx context.Context,
	id snowflake.ID,
) (*domain.OAuth2RefreshTokenStorage, error) {
	model := model.OAuth2RefreshTokenModel{}
	if err := xcontext.DB(ctx, repo.db).Take(&model, id).Error; err != nil {
		return nil, errordef.ConvertGormError(err)
	}

	return model.To(), nil
}

func (repo *OAuth2RefreshTokenRepository) Create(
	ctx context.Context,
	token *domain.OAuth2RefreshTokenStorage,
) error {
	return errordef.ConvertGormError(xcontext.DB(ctx, repo.db).Create(model.NewOAuth2RefreshTokenModel(token)).Error)
}

func (repo *OAuth2RefreshTokenRepository) Update(ctx context.Context, token *domain.OAuth2RefreshTokenStorage) error {
	result := xcontext.DB(ctx, repo.db).Model(&model.OAuth2RefreshTokenModel{}).
		Where("refresh_token_id=? AND seq=?", token.ID, token.SequenceNumber-1).
		Updates(map[string]any{
			"seq":             token.SequenceNumber,
			"access_token_id": token.AccessTokenID,
			"expires_at":      token.ExpiresAt,
		})

	if result.RowsAffected == 0 {
		return errordef.ErrNotFound
	}

	return errordef.ConvertGormError(result.Error)
}

func (repo *OAuth2RefreshTokenRepository) Delete(ctx context.Context, refreshTokenID snowflake.ID) error {
	return errordef.ConvertGormError(
		xcontext.DB(ctx, repo.db).Delete(&model.OAuth2RefreshTokenModel{}, refreshTokenID).Error)
}

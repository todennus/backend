package gorm

import (
	"context"

	"github.com/todennus/oauth2-service/infras/database/model"
	"github.com/todennus/shared/errordef"
	"github.com/xybor-x/snowflake"
	"gorm.io/gorm"
)

type RefreshTokenRepository struct {
	db *gorm.DB
}

func NewRefreshTokenRepository(db *gorm.DB) *RefreshTokenRepository {
	return &RefreshTokenRepository{db: db}
}

func (repo *RefreshTokenRepository) Create(
	ctx context.Context,
	refreshTokenId, accessTokenID snowflake.ID,
	seq int,
) error {
	return errordef.ConvertGormError(repo.db.WithContext(ctx).Create(&model.RefreshTokenModel{
		RefreshTokenID: refreshTokenId.Int64(),
		AccessTokenID:  accessTokenID.Int64(),
		Seq:            seq,
	}).Error)
}

func (repo *RefreshTokenRepository) UpdateByRefreshTokenID(
	ctx context.Context,
	refreshTokenID, accessTokenID snowflake.ID,
	expectedCurSeq int,
) error {
	result := repo.db.WithContext(ctx).Model(&model.RefreshTokenModel{}).
		Where("refresh_token_id=? AND seq=?", refreshTokenID, expectedCurSeq).
		Updates(map[string]any{
			"seq":             expectedCurSeq + 1,
			"access_token_id": accessTokenID,
		})

	if result.RowsAffected == 0 {
		return errordef.ErrNotFound
	}

	return errordef.ConvertGormError(result.Error)
}

func (repo *RefreshTokenRepository) DeleteByRefreshTokenID(
	ctx context.Context, refreshTokenID snowflake.ID,
) error {
	return errordef.ConvertGormError(repo.db.WithContext(ctx).Delete(&model.RefreshTokenModel{}, refreshTokenID).Error)
}

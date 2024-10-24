package model

import (
	"time"

	"github.com/todennus/backend/domain"
	"github.com/xybor-x/snowflake"
)

type SessionModel struct {
	State     int   `json:"state" session:"state"`
	UserID    int64 `json:"uid" session:"uid"`
	ExpiresAt int64 `json:"exp" session:"exp"`
}

func NewSession(usecase *domain.Session) *SessionModel {
	return &SessionModel{
		State:     int(usecase.State),
		UserID:    usecase.UserID.Int64(),
		ExpiresAt: usecase.ExpiresAt.UnixMilli(),
	}
}

func (m SessionModel) To() *domain.Session {
	return &domain.Session{
		State:     domain.SessionState(m.State),
		UserID:    snowflake.ID(m.UserID),
		ExpiresAt: time.UnixMilli(m.ExpiresAt),
	}
}

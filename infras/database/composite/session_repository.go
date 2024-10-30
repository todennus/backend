package composite

import (
	"context"

	"github.com/todennus/oauth2-service/domain"
	"github.com/todennus/oauth2-service/infras/database/model"
	"github.com/todennus/shared/xcontext"
	"github.com/todennus/x/session"
)

type SessionRepository struct {
	store session.Store[model.SessionModel]
}

func NewSessionRepository(store session.Store[model.SessionModel]) *SessionRepository {
	return &SessionRepository{store: store}
}

func (repo *SessionRepository) Load(ctx context.Context) (*domain.Session, error) {
	model, err := repo.store.Load(ctx, xcontext.Session(ctx))
	if err != nil {
		return nil, err
	}

	return model.To(), nil
}

func (repo *SessionRepository) Save(ctx context.Context, session *domain.Session) error {
	model := model.NewSession(session)

	return repo.store.Save(ctx, xcontext.Session(ctx), model)
}

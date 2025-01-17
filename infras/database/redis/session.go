package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/todennus/oauth2-service/infras/database/model"
	"github.com/todennus/shared/errordef"
	"github.com/todennus/x/session"
	"github.com/todennus/x/xcrypto"
)

const sessionIDLength = 16

func sessionKey(sid string) string {
	return fmt.Sprintf("session:%s", sid)
}

func userSessionsKey(uid int64, sid string) string {
	return fmt.Sprintf("user_sessions:%d:%s", uid, sid)
}

var _ session.Store[model.SessionModel] = (*RedisSessionStore)(nil)

type RedisSessionStore struct {
	client     *redis.Client
	expiration time.Duration
}

func NewRedisSessionStore(client *redis.Client, expiration time.Duration) *RedisSessionStore {
	return &RedisSessionStore{client: client, expiration: expiration}
}

func (store *RedisSessionStore) Load(ctx context.Context, session *session.Session) (*model.SessionModel, error) {
	if session.ID() == "" {
		return &model.SessionModel{}, nil
	}

	value, err := store.client.Get(ctx, sessionKey(session.ID())).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return &model.SessionModel{}, nil
		}

		return nil, err
	}

	sessionModel := model.SessionModel{}
	if err := json.Unmarshal([]byte(value), &sessionModel); err != nil {
		return nil, err
	}

	return &sessionModel, nil
}

func (store *RedisSessionStore) Save(ctx context.Context, session *session.Session, obj *model.SessionModel) error {
	modelJSON, err := json.Marshal(obj)
	if err != nil {
		return err
	}

	sid := session.ID()
	if sid == "" {
		sid = xcrypto.RandString(sessionIDLength)
	}

	if err := store.client.SetEx(ctx, sessionKey(sid), modelJSON, store.expiration).Err(); err != nil {
		return errordef.ConvertRedisError(err)
	}

	// TODO: Using SAdd instead. But we need to turn on the expired event of
	// redis, then remove the corresponding userSessions member.
	if err = store.client.SetEx(ctx, userSessionsKey(obj.UserID, sid), 1, store.expiration).Err(); err != nil {
		return errordef.ConvertRedisError(err)
	}

	session.SetID(sid)
	return nil
}

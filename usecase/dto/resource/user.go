package resource

import (
	"context"

	"github.com/todennus/oauth2-service/domain"
	"github.com/todennus/shared/enumdef"
	"github.com/todennus/shared/scopedef"
	"github.com/todennus/x/enum"
	"github.com/xybor-x/snowflake"
)

type User struct {
	ID          snowflake.ID
	Username    string
	DisplayName string
	Role        enum.Enum[enumdef.UserRole]
}

func NewUser(ctx context.Context, user *domain.User) *User {
	usecaseUser := &User{
		ID:          user.ID,
		Username:    user.Username,
		DisplayName: user.DisplayName,
		Role:        user.Role,
	}

	Set(ctx, &usecaseUser.Role, enum.Default[enumdef.UserRole]()).
		WhenRequestUserNot(user.ID).
		WhenNotContainsScope(scopedef.Engine.New(scopedef.Actions.Read, scopedef.Resources.User.Role))

	return usecaseUser
}

func NewUserWithoutFilter(user *domain.User) *User {
	usecaseUser := &User{
		ID:          user.ID,
		Username:    user.Username,
		DisplayName: user.DisplayName,
		Role:        user.Role,
	}

	return usecaseUser
}

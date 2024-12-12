package domain

import (
	"github.com/todennus/shared/enumdef"
	"github.com/xybor-x/snowflake"
)

type User struct {
	ID          snowflake.ID
	Username    string
	DisplayName string
	Role        enumdef.UserRole
}

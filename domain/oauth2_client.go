package domain

import (
	"github.com/xybor-x/snowflake"
)

type OAuth2Client struct {
	ID      snowflake.ID
	Name    string
	IsAdmin bool
}

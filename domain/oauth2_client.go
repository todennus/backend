package domain

import (
	"github.com/todennus/x/scope"
	"github.com/xybor-x/snowflake"
)

type OAuth2Client struct {
	ID           snowflake.ID
	Name         string
	AllowedScope scope.Scopes
}

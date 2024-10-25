package domain

import (
	"fmt"

	"github.com/todennus/shared/errordef"
)

var (
	ErrMismatchedPassword = fmt.Errorf("%w%s", errordef.ErrDomainKnown, "mismatched password")
	ErrClientInvalid      = fmt.Errorf("%w%s", errordef.ErrDomainKnown, "invalid client")
	ErrClientNameInvalid  = fmt.Errorf("%w%s", errordef.ErrDomainKnown, "invalid client name")
)

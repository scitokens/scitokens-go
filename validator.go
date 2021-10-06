package scitokens

import (
	"context"
	"fmt"
	"path"

	"github.com/lestrrat-go/jwx/jwt"
)

// Validator describes the interface to validate a SciToken. Right now it's just
// a convenience wrapper around jwt.Validator.
type Validator interface {
	jwt.Validator
}

type scopeValidator struct {
	scope Scope
}

// WithScope validates that the token is allowed to perform the scopes operation
// on the scopes path or a sub-path.
func WithScope(scope Scope) Validator {
	return scopeValidator{scope}
}

func (v scopeValidator) Validate(ctx context.Context, t jwt.Token) error {
	st, ok := t.(SciToken)
	if !ok {
		return NotSciTokenError
	}
	for _, ss := range st.Scopes() {
		if ss.Allowed(v.scope.Auth, v.scope.Path) {
			return nil
		}
	}
	return fmt.Errorf("missing the following scope: %s", v.scope)
}

type groupValidator struct {
	group string
}

// WithGroup validates that the token contains the group (exactly, leading slash
// optional) in wlcg.groups.
func WithGroup(group string) Validator {
	return groupValidator{path.Join("/", group)}
}

func (v groupValidator) Validate(ctx context.Context, t jwt.Token) error {
	st, ok := t.(SciToken)
	if !ok {
		return NotSciTokenError
	}
	for _, gg := range st.Groups() {
		if gg == v.group {
			return nil
		}
	}
	return fmt.Errorf("missing the following group: %s", v.group)
}

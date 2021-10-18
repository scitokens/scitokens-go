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

// AnyAudiences is the list of special wildcard audiences that a token can
// present to be used anywhere that otherwise accepts it.
//
// * ANY ([SciTokens](https://scitokens.org/technical_docs/Claims.html))
// * https://wlcg.cern.ch/jwt/v1/any ([WLCG](https://zenodo.org/record/3460258))
var AnyAudiences = []string{
	"ANY",
	"https://wlcg.cern.ch/jwt/v1/any",
}

type audienceValidator struct {
	audience string
}

// WithAudience validates that the token has the given audience or one of the
// supported "any" audiences.
func WithAudience(audience string) Validator {
	return audienceValidator{audience}
}

func (v audienceValidator) Validate(ctx context.Context, t jwt.Token) error {
	st, ok := t.(SciToken)
	if !ok {
		return NotSciTokenError
	}

	auds := st.Audience()
	if len(auds) == 0 {
		ver := st.Version()
		// The aud claim is OPTIONAL in scitoken version 1.0, mandatory in 2.0
		// and WLCG profile tokens.
		if ver == "" || ver == "scitoken:1.0" {
			return nil
		}
		return fmt.Errorf("aud claim is mandatory")
	}

	// are we one of the target audience or does the token have one of the
	// recognized "any" audiences?
	for _, aud := range auds {
		if aud == v.audience {
			return nil
		}
		for _, any := range AnyAudiences {
			if aud == any {
				return nil
			}
		}
	}

	return fmt.Errorf("expected audience %s or %v, token has %v", v.audience, AnyAudiences, t.Audience())
}

package scitokens

import (
	"context"
	"fmt"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

// Enforcer verifies that SciTokens https://scitokens.org are valid, from a
// certain issuer, and that they allow the requested resource.
type Enforcer struct {
	Issuer string
	keys   jwk.Set
}

// NewEnforcer initializes a new enforcer for validating SciTokens from the
// provided issuer.
func NewEnforcer(issuer string) (*Enforcer, error) {
	keys, err := GetIssuerKeys(context.Background(), issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch keyset: %s", err)
	}
	return &Enforcer{
		Issuer: issuer,
		keys:   keys,
	}, nil
}

// ValidateTokenString validates that the SciToken in the provided string is
// valid and meets all constraints imposed by the Enforcer.
func (e *Enforcer) ValidateTokenString(tokenstring string) error {
	t, err := jwt.ParseString(tokenstring, jwt.WithKeySet(e.keys))
	if err != nil {
		return fmt.Errorf("failed to parse token from string: %s", err)
	}
	printToken(t)
	return e.validate(t)
}

func (e *Enforcer) validate(t jwt.Token) error {
	err := jwt.Validate(t, jwt.WithIssuer(e.Issuer))
	if err != nil {
		return fmt.Errorf("failed to validate token: %s", err)
	}
	return nil
}

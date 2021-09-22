package scitokens

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

// Enforcer verifies that SciTokens https://scitokens.org are valid, from a
// certain issuer, and that they allow the requested resource.
type Enforcer struct {
	Issuer string
	keys   jwk.Set
	scopes []string
	logger io.Writer
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
		scopes: make([]string, 0),
	}, nil
}

// SetLogger sends verbose logging to the provided io.Writer.
func (e *Enforcer) SetLogger(w io.Writer) {
	e.logger = w
}

// RequireScope adds authz to optional path(s) to scopes to validate.
func (e *Enforcer) RequireScope(authz string, paths ...string) error {
	if len(paths) == 0 {
		e.scopes = append(e.scopes, authz)
	} else {
		for _, p := range paths {
			e.scopes = append(e.scopes, authz+":"+p)
		}
	}
	return nil
}

// ValidateTokenString validates that the SciToken in the provided string is
// valid and meets all constraints imposed by the Enforcer.
func (e *Enforcer) ValidateTokenString(tokenstring string) error {
	t, err := jwt.ParseString(tokenstring, jwt.WithKeySet(e.keys))
	if err != nil {
		return fmt.Errorf("failed to parse token from string: %s", err)
	}
	e.log(t)
	return e.validate(t)
}

// ValidateTokenReader validates that the SciToken read from the provided
// io.Reader is valid and meets all constraints imposed by the Enforcer.
func (e *Enforcer) ValidateTokenReader(r io.Reader) error {
	t, err := jwt.ParseReader(r, jwt.WithKeySet(e.keys))
	if err != nil {
		return fmt.Errorf("failed to parse token: %s", err)
	}
	e.log(t)
	return e.validate(t)
}

func (e *Enforcer) log(t jwt.Token) {
	if e.logger != nil {
		printToken(t, e.logger)
	}
}

func (e *Enforcer) validate(t jwt.Token) error {
	// validate standard claims
	err := jwt.Validate(t,
		jwt.WithIssuer(e.Issuer),
		jwt.WithRequiredClaim("scope"),
	)
	if err != nil {
		return err
	}

	// no scopes to validate
	if len(e.scopes) == 0 {
		return nil
	}

	// validate scopes
	scopeint, ok := t.Get("scope")
	if !ok {
		return fmt.Errorf("scope claim missing")
	}
	scopestr, ok := scopeint.(string)
	if !ok {
		return fmt.Errorf("unable to cast scopes claim to string")
	}
	scopes := strings.Split(scopestr, " ")
	scopemap := make(map[string]bool, len(scopes))
	for _, s := range scopes {
		scopemap[s] = true
	}
	missingScopes := make([]string, 0)
	for _, s := range e.scopes {
		if _, ok := scopemap[s]; !ok {
			missingScopes = append(missingScopes, s)
		}
	}
	if len(missingScopes) > 0 {
		return fmt.Errorf("missing the following scopes: %s", strings.Join(missingScopes, ","))
	}
	return nil
}

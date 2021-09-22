package scitokens

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

// Scope represents a token authorization scope, with optional path.
type Scope struct {
	Auth string
	Path string
}

// ParseScope parses a scope string like AUTHZ[:PATH].
func ParseScope(s string) Scope {
	pts := strings.SplitN(s, ":", 2)
	if len(pts) == 1 {
		return Scope{pts[0], ""}
	}
	return Scope{pts[0], pts[1]}
}

// String returns the string representation of the scope.
func (s Scope) String() string {
	if s.Path != "" {
		return s.Auth + ":" + s.Path
	}
	return s.Auth
}

// Allowed returns true if operation on path (can be empty string) is allowed by
// this scope. If path is a sub-path under the scope's path then it is allowed,
// e.g. if the scope path is write:/baz then operation=write and path=/baz/qux
// is allowed.
func (s Scope) Allowed(operation string, path string) bool {
	return s.Auth == operation && strings.HasPrefix(path, s.Path)
}

// Enforcer verifies that SciTokens https://scitokens.org are valid, from a
// certain issuer, and that they allow the requested resource.
//
// TODO: obtain issuer from token and provide the enforcer with a list of
// allowed issuers.
type Enforcer struct {
	Issuer string
	keys   jwk.Set
	scopes []Scope
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
		scopes: make([]Scope, 0),
	}, nil
}

// SetLogger sends verbose logging to the provided io.Writer.
func (e *Enforcer) SetLogger(w io.Writer) {
	e.logger = w
}

// RequireScope adds s to scopes to validate.
func (e *Enforcer) RequireScope(s Scope) error {
	e.scopes = append(e.scopes, s)
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
	hasScopes := make([]Scope, len(scopes))
	for _, s := range scopes {
		hasScopes = append(hasScopes, ParseScope(s))
	}
	missingScopes := make([]string, 0)
OUTER:
	for _, s := range e.scopes {
		for _, ss := range hasScopes {
			if ss.Allowed(s.Auth, s.Path) {
				continue OUTER
			}
		}
		missingScopes = append(missingScopes, s.String())
	}
	if len(missingScopes) > 0 {
		return fmt.Errorf("missing the following scopes: %s", strings.Join(missingScopes, ","))
	}
	return nil
}

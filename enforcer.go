package scitokens

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"path"
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
type Enforcer struct {
	issuers map[string]bool
	keys    jwk.Set
	scopes  []Scope
	groups  []string
	logger  io.Writer
}

// NewEnforcer initializes a new enforcer for validating SciTokens from the
// provided issuer(s).
func NewEnforcer(issuers ...string) (*Enforcer, error) {
	if len(issuers) == 0 {
		return nil, fmt.Errorf("must accept at least one issuer")
	}
	e := Enforcer{
		issuers: make(map[string]bool),
		scopes:  make([]Scope, 0),
		groups:  make([]string, 0),
	}
	for _, i := range issuers {
		if err := e.AddIssuer(context.Background(), i); err != nil {
			return nil, err
		}
	}
	return &e, nil
}

// AddIssuer adds an accepted issuer and fetches its signing keys.
func (e *Enforcer) AddIssuer(ctx context.Context, issuer string) error {
	keys, err := GetIssuerKeys(ctx, issuer)
	if err != nil {
		return fmt.Errorf("failed to fetch keyset for issuer %s: %s", issuer, err)
	}
	if e.keys == nil {
		e.keys = keys
	} else {
		// Merge keys into existing KeySet. Ideally we'd maintain multiple
		// keysets and pick at token parse time, but this is not currently
		// feasible. See https://github.com/lestrrat-go/jwx/issues/474.
		iter := keys.Iterate(ctx)
		for iter.Next(ctx) {
			k, ok := iter.Pair().Value.(jwk.Key)
			if !ok {
				return fmt.Errorf("iterating over keys yielded a non-key")
			}
			e.keys.Add(k)
		}
	}
	e.issuers[issuer] = true
	return nil
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

// RequireGroup adds group to the WLCG groups to validate. The leading slash is
// optional.
func (e *Enforcer) RequireGroup(group string) error {
	e.groups = append(e.groups, path.Join("/", group))
	return nil
}

// ValidateTokenString validates that the SciToken in the provided string is
// valid and meets all constraints imposed by the Enforcer.
func (e *Enforcer) ValidateTokenString(tokenstring string) error {
	t, err := jwt.ParseString(tokenstring, jwt.WithKeySet(e.keys))
	if err != nil {
		return &TokenParseError{err}
	}
	e.log(t)
	return e.Validate(t)
}

// ValidateTokenReader validates that the SciToken read from the provided
// io.Reader is valid and meets all constraints imposed by the Enforcer.
func (e *Enforcer) ValidateTokenReader(r io.Reader) error {
	t, err := jwt.ParseReader(r, jwt.WithKeySet(e.keys))
	if err != nil {
		return &TokenParseError{err}
	}
	e.log(t)
	return e.Validate(t)
}

// ValidateTokenRequest validates that the SciToken read from the provided
// http.Request is valid and meets all constraints imposed by the Enforcer.
//
// The token is returned and can be re-validated with Validate().
func (e *Enforcer) ValidateTokenRequest(r *http.Request) (jwt.Token, error) {
	t, err := jwt.ParseRequest(r, jwt.WithKeySet(e.keys))
	if err != nil {
		return nil, &TokenParseError{err}
	}
	e.log(t)
	return t, e.Validate(t)
}

func (e *Enforcer) log(t jwt.Token) {
	if e.logger != nil {
		printToken(t, e.logger)
	}
}

// Validate checks that the SciToken is valid and meets all constraints imposed
// by the Enforcer. This can be called multiple times, e.g. to test the token
// against different scopes.
func (e *Enforcer) Validate(t jwt.Token) error {
	// validate standard claims
	if _, ok := e.issuers[t.Issuer()]; !ok {
		return &TokenValidationError{fmt.Errorf("untrusted issuer %s", t.Issuer())}
	}
	err := jwt.Validate(t,
		jwt.WithRequiredClaim("scope"),
	)
	if err != nil {
		return &TokenValidationError{err}
	}

	if len(e.scopes) > 0 {
		if err := e.validateScopes(t); err != nil {
			return err
		}
	}

	if len(e.groups) > 0 {
		if err := e.validateGroups(t); err != nil {
			return err
		}
	}

	return nil
}

func (e *Enforcer) validateScopes(t jwt.Token) error {
	scopeint, ok := t.Get("scope")
	if !ok {
		return &TokenValidationError{fmt.Errorf("scope claim missing")}
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
		return &TokenValidationError{fmt.Errorf("missing the following scopes: %s", strings.Join(missingScopes, ","))}
	}

	return nil
}

func (e *Enforcer) validateGroups(t jwt.Token) error {
	groupint, ok := t.Get("wlcg.groups")
	if !ok {
		return &TokenValidationError{fmt.Errorf("wlcg.groups claim missing")}
	}
	groupints, ok := groupint.([]interface{})
	if !ok {
		return fmt.Errorf("unable to cast wlcg.groups claim to slice")
	}
	groups := make([]string, len(groupints))
	for _, g := range groupints {
		gs, ok := g.(string)
		if !ok {
			return fmt.Errorf("unable to cast wlcg.group \"%v\" to string", g)
		}
		groups = append(groups, gs)
	}
	if !ok {
	}
	missingGroups := make([]string, 0)
OUTER:
	for _, g := range e.groups {
		for _, gg := range groups {
			if gg == g {
				continue OUTER
			}
		}
		missingGroups = append(missingGroups, g)
	}
	if len(missingGroups) > 0 {
		return &TokenValidationError{fmt.Errorf("missing the following groups: %s", strings.Join(missingGroups, ","))}
	}

	return nil
}

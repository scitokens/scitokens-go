package scitokens

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

// Enforcer verifies that SciTokens https://scitokens.org are valid, from a
// certain issuer, and that they allow the requested resource.
type Enforcer struct {
	issuers map[string]bool
	keys    jwk.Set
	scopes  []Scope
	groups  []string
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

func (e *Enforcer) parseOptions() []jwt.ParseOption {
	return []jwt.ParseOption{
		jwt.WithKeySet(e.keys),
	}
}

// ValidateToken parses and validates that the SciToken in the provided byte
// slice is valid and meets all constraints imposed by the Enforcer (see
// Validate).
//
// The token is returned and can be re-validated with Validate(). Currently a
// vanilla jwt.Token is returned, but at some point this may be expanded to a
// custom SciToken type (which will still implement jwt.Token).
func (e *Enforcer) ValidateToken(token []byte) (jwt.Token, error) {
	t, err := jwt.Parse(token, e.parseOptions()...)
	if err != nil {
		return nil, &TokenParseError{err}
	}
	return t, e.Validate(t)
}

// ValidateTokenString parses and validates that the SciToken in the provided
// string is valid and meets all constraints imposed by the Enforcer.
// See ValidateToken.
func (e *Enforcer) ValidateTokenString(tokenstring string) (jwt.Token, error) {
	t, err := jwt.ParseString(tokenstring, e.parseOptions()...)
	if err != nil {
		return nil, &TokenParseError{err}
	}
	return t, e.Validate(t)
}

// ValidateTokenReader parses and validates that the SciToken read from the
// provided io.Reader is valid and meets all constraints imposed by the
// Enforcer. See ValidateToken.
func (e *Enforcer) ValidateTokenReader(r io.Reader) (jwt.Token, error) {
	t, err := jwt.ParseReader(r, e.parseOptions()...)
	if err != nil {
		return nil, &TokenParseError{err}
	}
	return t, e.Validate(t)
}

// ValidateTokenForm parses and validates that the SciToken read from the
// provided url value is valid and meets all constraints imposed by the
// Enforcer. See ValidateToken.
func (e *Enforcer) ValidateTokenForm(values url.Values, name string) (jwt.Token, error) {
	t, err := jwt.ParseForm(values, name, e.parseOptions()...)
	if err != nil {
		return nil, &TokenParseError{err}
	}
	return t, e.Validate(t)
}

// ValidateTokenHeader parses and validates that the SciToken read from the
// provided http.Header is valid and meets all constraints imposed by the
// Enforcer. See ValidateToken.
func (e *Enforcer) ValidateTokenHeader(hdr http.Header, name string) (jwt.Token, error) {
	t, err := jwt.ParseHeader(hdr, name, e.parseOptions()...)
	if err != nil {
		return nil, &TokenParseError{err}
	}
	return t, e.Validate(t)
}

// ValidateTokenRequest parses and validates that the SciToken read from the
// provided http.Request is valid and meets all constraints imposed by the
// Enforcer. See ValidateToken.
func (e *Enforcer) ValidateTokenRequest(r *http.Request) (jwt.Token, error) {
	t, err := jwt.ParseRequest(r, e.parseOptions()...)
	if err != nil {
		return nil, &TokenParseError{err}
	}
	return t, e.Validate(t)
}

// Validate checks that the SciToken is valid and meets all constraints imposed
// by the Enforcer, namely:
// * the issuer is accepted (via AddIssuer) and the token was signed by it
// * all scopes added by RequiredScope are present in the scope claim
// * all groups added by RequiredGroup are present in the wlcg.groups claim
//
// This can be called multiple times, e.g. to test the token against different
// scopes.
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
	hasScopes, err := GetScopes(t)
	if err != nil {
		return err
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
	groups, err := GetGroups(t)
	if err != nil {
		return err
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

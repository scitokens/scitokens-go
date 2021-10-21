package scitokens

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	"github.com/lestrrat-go/jwx/jwt"
)

// Enforcer verifies that SciTokens https://scitokens.org are valid, from a
// certain issuer, and that they allow the requested resource.
type Enforcer struct {
	issuers    map[string]bool
	ikm        *IssuerKeyManager
	validators []Validator
}

// NewEnforcer initializes a new enforcer for validating SciTokens from the
// provided issuer(s). The context object should be cancelled when the process
// is done with the enforcer.
func NewEnforcer(ctx context.Context, issuers ...string) (*Enforcer, error) {
	if len(issuers) == 0 {
		return nil, errors.New("must accept at least one issuer")
	}
	e := Enforcer{
		issuers:    make(map[string]bool),
		ikm:        NewIssuerKeyManager(ctx),
		validators: make([]Validator, 0),
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
	err := e.ikm.AddIssuer(ctx, issuer)
	if err != nil {
		return fmt.Errorf("failed to fetch keyset for issuer %s: %w", issuer, err)
	}
	e.issuers[issuer] = true
	return nil
}

// RequireAudience adds aud to audiences to validate.
func (e *Enforcer) RequireAudience(aud string) error {
	return e.RequireValidator(WithAudience(aud))
}

// RequireScope adds s to scopes to validate.
func (e *Enforcer) RequireScope(s Scope) error {
	return e.RequireValidator(WithScope(s))
}

// RequireGroup adds group to the WLCG groups to validate. The leading slash is
// optional.
func (e *Enforcer) RequireGroup(group string) error {
	return e.RequireValidator(WithGroup(group))
}

// RequireValidator adds a general constraint.
func (e *Enforcer) RequireValidator(v Validator) error {
	e.validators = append(e.validators, v)
	return nil
}

func (e *Enforcer) parseOptions() []jwt.ParseOption {
	return []jwt.ParseOption{
		jwt.WithKeySetProvider(e.ikm),
		jwt.InferAlgorithmFromKey(true),
	}
}

// ValidateToken parses and validates that the SciToken in the provided byte
// slice is valid and meets all basic constraints imposed by the Enforcer along
// with the extra optional constraints, which can be defined using WithScope,
// WithGroup, etc.
//
// The token is returned and can be re-validated with Validate().
func (e *Enforcer) ValidateToken(token []byte, constraints ...Validator) (SciToken, error) {
	t, err := jwt.Parse(token, e.parseOptions()...)
	if err != nil {
		return nil, err
	}
	st, err := NewSciToken(t)
	if err != nil {
		return nil, err
	}
	return st, e.Validate(st, constraints...)
}

// ValidateTokenString parses and validates that the SciToken in the provided
// string is valid and meets all constraints imposed by the Enforcer.
// See ValidateToken.
func (e *Enforcer) ValidateTokenString(tokenstring string, constraints ...Validator) (SciToken, error) {
	t, err := jwt.ParseString(tokenstring, e.parseOptions()...)
	if err != nil {
		return nil, err
	}
	st, err := NewSciToken(t)
	if err != nil {
		return nil, err
	}
	return st, e.Validate(st, constraints...)
}

// ValidateTokenReader parses and validates that the SciToken read from the
// provided io.Reader is valid and meets all constraints imposed by the
// Enforcer. See ValidateToken.
func (e *Enforcer) ValidateTokenReader(r io.Reader, constraints ...Validator) (SciToken, error) {
	t, err := jwt.ParseReader(r, e.parseOptions()...)
	if err != nil {
		return nil, err
	}
	st, err := NewSciToken(t)
	if err != nil {
		return nil, err
	}
	return st, e.Validate(st, constraints...)
}

// ValidateTokenForm parses and validates that the SciToken read from the
// provided url value is valid and meets all constraints imposed by the
// Enforcer. See ValidateToken.
func (e *Enforcer) ValidateTokenForm(values url.Values, name string, constraints ...Validator) (SciToken, error) {
	t, err := jwt.ParseForm(values, name, e.parseOptions()...)
	if err != nil {
		return nil, err
	}
	st, err := NewSciToken(t)
	if err != nil {
		return nil, err
	}
	return st, e.Validate(st, constraints...)
}

// ValidateTokenHeader parses and validates that the SciToken read from the
// provided http.Header is valid and meets all constraints imposed by the
// Enforcer. See ValidateToken.
func (e *Enforcer) ValidateTokenHeader(hdr http.Header, name string, constraints ...Validator) (SciToken, error) {
	t, err := jwt.ParseHeader(hdr, name, e.parseOptions()...)
	if err != nil {
		return nil, err
	}
	st, err := NewSciToken(t)
	if err != nil {
		return nil, err
	}
	return st, e.Validate(st, constraints...)
}

// ValidateTokenRequest parses and validates that the SciToken read from the
// provided http.Request is valid and meets all constraints imposed by the
// Enforcer. See ValidateToken.
func (e *Enforcer) ValidateTokenRequest(r *http.Request, constraints ...Validator) (SciToken, error) {
	t, err := jwt.ParseRequest(r, e.parseOptions()...)
	if err != nil {
		return nil, err
	}
	st, err := NewSciToken(t)
	if err != nil {
		return nil, err
	}
	return st, e.Validate(st, constraints...)
}

// ValidateTokenEnvironment searches for a SciToken in the execution
// environment, per the following rules (https://doi.org/10.5281/zenodo.3937438),
// then parses and validates it meets all constraints imposed by the Enforcer:
//
//   1. If the BEARER_TOKEN environment variable is set, then the value is taken
//   to be the token contents.
//
//   2. If the BEARER_TOKEN_FILE environment variable is set, then its value is
//   interpreted as a filename. The contents of the specified file are taken to
//   be the token contents.
//
//   3. If the XDG_RUNTIME_DIR environment variable is set, then take the token
//   from the contents of $XDG_RUNTIME_DIR/bt_u$ID.
//
//   4. Otherwise, take the token from /$TMP/bt_u$ID, where $TMP is TMPDIR if
//   set, or /tmp or other OS-appropriate temp directory (see os.Tempdir())
//
// If no token is found in any of these locations, a TokenNotFoundError is
// returned.
func (e *Enforcer) ValidateTokenEnvironment(constraints ...Validator) (SciToken, error) {
	var data []byte
	if ts, ok := os.LookupEnv("BEARER_TOKEN"); ok {
		data = []byte(ts)
	} else {
		fname := tokenFilename()
		if fname == "" {
			return nil, TokenNotFoundError
		}
		var err error
		data, err = os.ReadFile(fname)
		if err != nil {
			return nil, fmt.Errorf("unable to read token from file %s: %w", fname, err)
		}
	}
	return e.ValidateToken(data, constraints...)
}

func tokenFilename() string {
	if f, ok := os.LookupEnv("BEARER_TOKEN_FILE"); ok {
		return f
	}
	if d, ok := os.LookupEnv("XDG_RUNTIME_DIR"); ok {
		f := filepath.Join(d, fmt.Sprintf("/bt_u%d", os.Getuid()))
		if _, err := os.Stat(f); err == nil {
			return f
		}
	}
	f := filepath.Join(os.TempDir(), fmt.Sprintf("/bt_u%d", os.Getuid()))
	if _, err := os.Stat(f); err == nil {
		return f
	}
	return ""
}

// Validate checks that the SciToken is valid and meets all constraints imposed
// by the Enforcer, namely:
//
// * the issuer is accepted (via AddIssuer) and the token was signed by it
//
// * all audiences added by RequireAudience or one of the recognized "any"
//   audiences are present in the aud claim.
//
// * all scopes added by RequireScope are present in the scope claim
//
// * all groups added by RequireGroup are present in the wlcg.groups claim
//
// This can be called multiple times, e.g. to test the token against different
// scopes.
func (e *Enforcer) Validate(t SciToken, constraints ...Validator) error {
	// validate standard claims
	if _, ok := e.issuers[t.Issuer()]; !ok {
		return &TokenValidationError{UntrustedIssuerError}
	}
	opts := make([]jwt.ValidateOption, len(e.validators)+len(constraints))
	for i, v := range e.validators {
		opts[i] = jwt.WithValidator(v)
	}
	for i, v := range constraints {
		opts[i+len(e.validators)] = jwt.WithValidator(v)
	}
	if err := jwt.Validate(t, opts...); err != nil {
		// It doesn't appear that Validate can return a non-validation error
		// (i.e. some internal error), and there's no way to differentiate if so
		// (besides error message parsing, bleh).
		return &TokenValidationError{err}
	}
	return nil
}

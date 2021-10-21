package scitokens

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/lestrrat-go/jwx/jwt"
	"github.com/stretchr/testify/assert"
)

func TestEnforcer(t *testing.T) {
	assert := assert.New(t)

	srv, err := newFakeAuthServer()
	if !assert.NoError(err) {
		return
	}
	ts := httptest.NewTLSServer(srv)
	defer ts.Close()
	http.DefaultClient = ts.Client()

	ctx := context.Background()

	t.Run("new enforcer", func(t *testing.T) {
		_, err = NewEnforcer()
		assert.Error(err, "at least one issuer must be specified")

		_, err := NewEnforcer(ts.URL)
		if !assert.NoError(err, "NewEnforcer should succeed") {
			return
		}
	})

	t.Run("new enforcer daemon", func(t *testing.T) {
		_, err = NewEnforcerDaemon(ctx)
		assert.Error(err, "at least one issuer must be specified")

		_, err = NewEnforcerDaemon(ctx, "https://example.com")
		assert.Error(err, "NewEnforcerDaemon should fail for invalid issuer")

		enf, err := NewEnforcerDaemon(ctx, ts.URL)
		if !assert.NoError(err, "NewEnforcerDaemon should succeed") {
			return
		}

		assert.NoError(enf.AddIssuer(ctx, ts.URL), "should be able to re-add issuer")
		assert.Error(enf.AddIssuer(ctx, "https://example.com"), "AddIssuer should fail for invalid issuer")
	})

	// generate a few tokens with different capabilities
	invalidTokens := make([][]byte, 4)
	invalidTokens[0] = []byte("not a token")
	invalidTokens[1], err = srv.MakeToken(ts.URL, 0, nil, nil)
	if !assert.NoError(err) {
		return
	}
	invalidTokens[2], err = srv.MakeToken(ts.URL, nil, 0, nil)
	if !assert.NoError(err) {
		return
	}
	// we explicitely test this token's validation error
	invalidIssuerToken, err := srv.MakeToken("https://example.com", nil, nil, nil)
	if !assert.NoError(err) {
		return
	}
	invalidTokens[3] = invalidIssuerToken

	// valid tokens
	t1, err := srv.MakeToken(ts.URL, nil, nil, nil)
	if !assert.NoError(err) {
		return
	}
	t2, err := srv.MakeToken(ts.URL, nil, []interface{}{"/foo"}, "bar")
	if !assert.NoError(err) {
		return
	}
	t3, err := srv.MakeToken(ts.URL, "compute", []interface{}{"/foo"}, "ANY")
	if !assert.NoError(err) {
		return
	}
	t4, err := srv.MakeToken(ts.URL, "compute read:/foo", []interface{}{"/foo"}, "foo")
	if !assert.NoError(err) {
		return
	}

	t.Run("validate token", func(t *testing.T) {
		enf, err := NewEnforcerDaemon(ctx, ts.URL)
		if !assert.NoError(err, "NewEnforcerDaemon should succeed") {
			return
		}

		for _, nt := range invalidTokens {
			_, err = enf.ValidateToken(nt)
			assert.Error(err)
		}

		// we have to go around the enforcer parsing to check the error handling in Validate
		// this also lets us test error types and wrapping explicitely
		jt, err := jwt.Parse(invalidIssuerToken)
		if !assert.NoError(err) {
			return
		}
		st, err := NewSciToken(jt)
		if !assert.NoError(err) {
			return
		}
		err = enf.Validate(st)
		e := &TokenValidationError{}
		assert.ErrorAs(err, &e)
		assert.ErrorIs(err, UntrustedIssuerError)

		st1, err := enf.ValidateToken(t1)
		assert.NoError(err, "ValidateToken should succeed for token with no scopes or groups")
		assert.Error(enf.Validate(st1, WithGroup("foo")), "Validate should fail for token missing required group")
		assert.Error(enf.Validate(st1, WithScope(Scope{"read", "/"})), "Validate should fail for token missing required scope")
		st2, err := enf.ValidateToken(t2)
		assert.NoError(err, "ValidateToken should succeed with no additional validators")
		st3, err := enf.ValidateToken(t3)
		assert.NoError(err, "ValidateToken should succeed with no additional validators")
		st4, err := enf.ValidateToken(t4)
		assert.NoError(err, "ValidateToken should succeed with no additional validators")

		if !assert.NoError(enf.RequireAudience("foo")) {
			return
		}
		assert.NoError(enf.Validate(st1), "ValidateToken should pass for token with no audience")
		assert.Error(enf.Validate(st2), "ValidateToken should fail for token missing required audience or ANY")
		assert.NoError(st2.Set("aud", "ANY"))
		assert.NoError(enf.Validate(st2), "ValidateToken should pass for token with any audience")
		assert.NoError(enf.Validate(st3), "ValidateToken should pass for token with any audience")
		assert.NoError(enf.Validate(st4), "ValidateToken should pass for token with required audience")

		if !assert.NoError(enf.RequireGroup("foo")) {
			return
		}
		assert.Error(enf.Validate(st1), "ValidateToken should fail for token missing required group")
		assert.NoError(enf.Validate(st2), "ValidateToken should succeed for token with required group")

		if !assert.NoError(enf.RequireScope(Scope{"compute", ""})) {
			return
		}
		assert.Error(enf.Validate(st1), "ValidateToken should fail for token missing required scope (1)")
		assert.Error(enf.Validate(st2), "ValidateToken should fail for token missing required scope (2)")
		assert.NoError(enf.Validate(st3), "ValidateToken should succeed for token with required scope")

		if !assert.NoError(enf.RequireValidator(WithScope(Scope{"read", "/foo"}))) {
			return
		}
		assert.Error(enf.Validate(st1), "ValidateToken should fail for token missing required scope path (1)")
		assert.Error(enf.Validate(st2), "ValidateToken should fail for token missing required scope path (2)")
		assert.Error(enf.Validate(st3), "ValidateToken should fail for token missing required scope path (3)")
		assert.NoError(enf.Validate(st4), "ValidateToken should succeed for token with required scope path")

		assert.Error(enf.Validate(st4, WithScope(Scope{"read", "/bar"})), "ValidateToken should fail for token missing required scope path (4)")
		assert.Error(enf.Validate(st4, WithScope(Scope{"write", "/foo"})), "ValidateToken should fail for token missing required scope (3)")
		assert.NoError(enf.Validate(st4, WithScope(Scope{"read", "/foo/bar"})), "ValidateToken should succeed for token with required scope parent path")

	})

	t.Run("validate token from string", func(t *testing.T) {
		enf, err := NewEnforcerDaemon(ctx, ts.URL)
		if !assert.NoError(err, "NewEnforcerDaemon should succeed") {
			return
		}

		for _, nt := range invalidTokens {
			_, err = enf.ValidateTokenString(string(nt))
			assert.Error(err)
		}

		_, err = enf.ValidateTokenString(string(t1))
		assert.NoError(err, "ValidateTokenString should succeed")
	})

	t.Run("validate token from Reader", func(t *testing.T) {
		enf, err := NewEnforcerDaemon(ctx, ts.URL)
		if !assert.NoError(err, "NewEnforcerDaemon should succeed") {
			return
		}

		r := &bytes.Reader{}
		for _, nt := range invalidTokens {
			r.Reset(nt)
			_, err = enf.ValidateTokenReader(r)
			assert.Error(err)
		}

		r.Reset(t1)
		_, err = enf.ValidateTokenReader(r)
		assert.NoError(err, "ValidateTokenReader should succeed")
	})

	t.Run("validate token from form value", func(t *testing.T) {
		enf, err := NewEnforcerDaemon(ctx, ts.URL)
		if !assert.NoError(err, "NewEnforcerDaemon should succeed") {
			return
		}
		v := url.Values{}
		for _, nt := range invalidTokens {
			v.Set("token", string(nt))
			_, err = enf.ValidateTokenForm(v, "token")
			assert.Error(err)
		}

		v.Set("token", string(t1))
		_, err = enf.ValidateTokenForm(v, "token")
		assert.NoError(err, "ValidateTokenForm should succeed")
	})

	t.Run("validate token from header value", func(t *testing.T) {
		enf, err := NewEnforcerDaemon(ctx, ts.URL)
		if !assert.NoError(err, "NewEnforcerDaemon should succeed") {
			return
		}
		h := http.Header{}
		for _, nt := range invalidTokens {
			h.Set("X-SciToken", string(nt))
			_, err = enf.ValidateTokenHeader(h, "X-SciToken")
			assert.Error(err)
		}

		h.Set("X-SciToken", string(t1))
		// For the header "Authorization", it will strip the prefix "Bearer "
		// and will treat the remaining value as a JWT.
		h.Set("Authorization", "Bearer "+string(t1))

		_, err = enf.ValidateTokenHeader(h, "X-SciToken")
		assert.NoError(err, "ValidateTokenHeader should succeed for X-SciToken header")

		_, err = enf.ValidateTokenHeader(h, "Authorization")
		assert.NoError(err, "ValidateTokenHeader should succeed for Authorization header")
	})

	t.Run("validate token from http request", func(t *testing.T) {
		enf, err := NewEnforcerDaemon(ctx, ts.URL)
		if !assert.NoError(err, "NewEnforcerDaemon should succeed") {
			return
		}
		r := httptest.NewRequest("GET", "https://example.com/foo", nil)
		for _, nt := range invalidTokens {
			r.Header.Set("Authorization", "Bearer "+string(nt))
			_, err = enf.ValidateTokenRequest(r)
			assert.Error(err)
		}

		r.Header.Set("Authorization", "Bearer "+string(t1))
		_, err = enf.ValidateTokenRequest(r)
		assert.NoError(err, "ValidateTokenRequest should succeed")
	})

	t.Run("validate token from environment", func(t *testing.T) {
		enf, err := NewEnforcerDaemon(ctx, ts.URL)
		if !assert.NoError(err, "NewEnforcerDaemon should succeed") {
			return
		}

		resetEnv := clearEnv("BEARER_TOKEN", "BEARER_TOKEN_FILE", "XDG_RUNTIME_DIR", "TMPDIR")
		defer resetEnv()

		_, err = enf.ValidateTokenEnvironment()
		assert.ErrorIs(err, TokenNotFoundError, "ValidateTokenEnvironment should return TokenNotFoundError")

		for _, nt := range invalidTokens {
			if !assert.NoError(os.Setenv("BEARER_TOKEN", string(nt))) {
				return
			}
			_, err = enf.ValidateTokenEnvironment()
			assert.Error(err)
		}

		if !assert.NoError(os.Setenv("BEARER_TOKEN", string(t1))) {
			return
		}
		_, err = enf.ValidateTokenEnvironment()
		assert.NoError(err, "ValidateTokenEnvironment should succeed for BEARER_TOKEN var")
		os.Unsetenv("BEARER_TOKEN")

		// create temporary directory to use for token files
		dir, err := os.MkdirTemp("", "scitokentest")
		if !assert.NoError(err, "MkdirTemp should succeed") {
			return
		}
		defer os.RemoveAll(dir)

		file := filepath.Join(dir, fmt.Sprintf("/bt_u%d", os.Getuid()))
		if !assert.NoError(os.WriteFile(file, t1, 0600), "WriteFile should succeed") {
			return
		}

		os.Setenv("BEARER_TOKEN_FILE", file)
		_, err = enf.ValidateTokenEnvironment()
		assert.NoError(err, "ValidateTokenEnvironment should succeed for BEARER_TOKEN_FILE var")
		os.Unsetenv("BEARER_TOKEN_FILE")

		os.Setenv("XDG_RUNTIME_DIR", dir)
		_, err = enf.ValidateTokenEnvironment()
		assert.NoError(err, "ValidateTokenEnvironment should succeed for XDG_RUNTIME_DIR var")
		os.Unsetenv("XDG_RUNTIME_DIR")

		os.Setenv("TMPDIR", dir)
		_, err = enf.ValidateTokenEnvironment()
		assert.NoError(err, "ValidateTokenEnvironment should succeed for TMPDIR var")
		os.Unsetenv("TMPDIR")

		// create unreadable file to test error handling
		if !assert.NoError(os.Remove(file), "Remove should succeed") {
			return
		}
		if !assert.NoError(os.WriteFile(file, t1, 0000), "WriteFile should succeed") {
			return
		}
		os.Setenv("BEARER_TOKEN_FILE", file)
		_, err = enf.ValidateTokenEnvironment()
		assert.Error(err, "ValidateTokenEnvironment should fail for unreadable token file")
		os.Unsetenv("BEARER_TOKEN_FILE")
	})
}

// clearEnv clears the given env vars, and returns a function that will reset
// them to their current values (if set).
func clearEnv(vars ...string) func() {
	origin := make(map[string]string, len(vars))
	for _, k := range vars {
		if v, ok := os.LookupEnv(k); ok {
			origin[k] = v
			os.Unsetenv(k)
		}
	}
	return func() {
		for k, v := range origin {
			os.Setenv(k, v)
		}
	}
}

func TestClearEnv(t *testing.T) {
	testvars := []string{"CLEARENV_TEST1", "CLEARENV_TEST2", "CLEARENV_TEST3"}
	for _, v := range testvars {
		if _, ok := os.LookupEnv(v); ok {
			t.Errorf("env var %s already set, won't continue", v)
			return
		}
		os.Setenv(v, "foo")
	}
	// verify that they're set
	for _, v := range testvars {
		_, ok := os.LookupEnv(v)
		assert.True(t, ok)
	}

	// clear and verify
	f := clearEnv(testvars...)
	for _, v := range testvars {
		_, ok := os.LookupEnv(v)
		assert.False(t, ok)
	}

	// reset and verify
	f()
	for _, v := range testvars {
		_, ok := os.LookupEnv(v)
		assert.True(t, ok)
	}

	// clean up
	clearEnv(testvars...)
}

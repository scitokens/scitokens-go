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
		_, err = NewEnforcer(ctx)
		assert.Error(err, "at least one issuer must be specified")

		_, err = NewEnforcer(ctx, "https://example.com")
		assert.Error(err, "NewEnforcer should fail for invalid issuer")

		enf, err := NewEnforcer(ctx, ts.URL)
		if !assert.NoError(err, "NewEnforcer should succeed") {
			return
		}

		assert.NoError(enf.AddIssuer(ctx, ts.URL), "should be able to re-add issuer")
		assert.Error(enf.AddIssuer(ctx, "https://example.com"), "AddIssuer should fail for invalid issuer")
	})

	// generate a few tokens with different capabilities
	// TODO probably a better way to organize these and make sure they get used correctly.

	// invalid tokens
	nt1 := []byte("not a token")
	nt2, err := srv.MakeToken(ts.URL, 0, nil)
	if !assert.NoError(err) {
		return
	}
	nt3, err := srv.MakeToken(ts.URL, nil, 0)
	if !assert.NoError(err) {
		return
	}
	nt4, err := srv.MakeToken("https://example.com", nil, nil)
	if !assert.NoError(err) {
		return
	}

	// valid tokens
	t1, err := srv.MakeToken(ts.URL, nil, nil)
	if !assert.NoError(err) {
		return
	}
	t2, err := srv.MakeToken(ts.URL, nil, []interface{}{"/foo"})
	if !assert.NoError(err) {
		return
	}
	t3, err := srv.MakeToken(ts.URL, "compute", []interface{}{"/foo"})
	if !assert.NoError(err) {
		return
	}
	t4, err := srv.MakeToken(ts.URL, "compute read:/foo", []interface{}{"/foo"})
	if !assert.NoError(err) {
		return
	}

	t.Run("validate token", func(t *testing.T) {
		enf, err := NewEnforcer(ctx, ts.URL)
		if !assert.NoError(err, "NewEnforcer should succeed") {
			return
		}

		_, err = enf.ValidateToken(nt1)
		assert.EqualError(err, "error while parsing token: failed to parse token: invalid character 'o' in literal null (expecting 'u')")

		_, err = enf.ValidateToken(nt2)
		assert.EqualError(err, "error while parsing token: unable to cast scopes claim to string")

		_, err = enf.ValidateToken(nt3)
		assert.EqualError(err, "error while parsing token: unable to cast wlcg.groups claim to slice")

		_, err = enf.ValidateToken(nt4)
		assert.ErrorIs(err, UntrustedIssuerError)

		// we have to go around the enforcer parsing to check the logic in Validate
		jnt4, err := jwt.Parse(nt4)
		if !assert.NoError(err) {
			return
		}
		snt4, err := NewSciToken(jnt4)
		if !assert.NoError(err) {
			return
		}
		err = enf.Validate(snt4)
		assert.ErrorIs(err, UntrustedIssuerError)
		assert.EqualError(err, "token invalid: issuer not trusted")

		st1, err := enf.ValidateToken(t1)
		assert.NoError(err, "ValidateToken should succeed for token with no scopes or groups")
		assert.Error(enf.Validate(st1, WithGroup("foo")), "Validate should fail for token missing required group")
		assert.Error(enf.Validate(st1, WithScope(Scope{"read", "/"})), "Validate should fail for token missing required scope")

		if !assert.NoError(enf.RequireGroup("foo")) {
			return
		}
		assert.Error(enf.Validate(st1), "ValidateToken should fail for token missing required group")
		st2, err := enf.ValidateToken(t2)
		assert.NoError(err, "ValidateToken should succeed for token with required group")

		if !assert.NoError(enf.RequireScope(Scope{"compute", ""})) {
			return
		}
		assert.Error(enf.Validate(st1), "ValidateToken should fail for token missing required scope (1)")
		assert.Error(enf.Validate(st2), "ValidateToken should fail for token missing required scope (2)")
		st3, err := enf.ValidateToken(t3)
		assert.NoError(err, "ValidateToken should succeed for token with required scope")

		if !assert.NoError(enf.RequireValidator(WithScope(Scope{"read", "/foo"}))) {
			return
		}
		assert.Error(enf.Validate(st1), "ValidateToken should fail for token missing required scope path (1)")
		assert.Error(enf.Validate(st2), "ValidateToken should fail for token missing required scope path (2)")
		assert.Error(enf.Validate(st3), "ValidateToken should fail for token missing required scope path (3)")
		st4, err := enf.ValidateToken(t4)
		assert.NoError(err, "ValidateToken should succeed for token with required scope path")

		assert.Error(enf.Validate(st4, WithScope(Scope{"read", "/bar"})), "ValidateToken should fail for token missing required scope path (4)")
		assert.Error(enf.Validate(st4, WithScope(Scope{"write", "/foo"})), "ValidateToken should fail for token missing required scope (3)")
		assert.NoError(enf.Validate(st4, WithScope(Scope{"read", "/foo/bar"})), "ValidateToken should succeed for token with required scope parent path")
	})

	t.Run("validate token from string", func(t *testing.T) {
		enf, err := NewEnforcer(ctx, ts.URL)
		if !assert.NoError(err, "NewEnforcer should succeed") {
			return
		}
		_, err = enf.ValidateTokenString(string(nt1))
		assert.Error(err, "ValidateTokenString should fail for invalid token")

		_, err = enf.ValidateTokenString(string(nt2))
		assert.Error(err, "ValidateTokenString should fail for token with invalid scope")

		_, err = enf.ValidateTokenString(string(t1))
		assert.NoError(err, "ValidateTokenString should succeed")
	})

	t.Run("validate token from Reader", func(t *testing.T) {
		enf, err := NewEnforcer(ctx, ts.URL)
		if !assert.NoError(err, "NewEnforcer should succeed") {
			return
		}
		r := bytes.NewReader(nt1)
		_, err = enf.ValidateTokenReader(r)
		assert.Error(err, "ValidateTokenReader should fail for invalid token")

		r.Reset(nt2)
		_, err = enf.ValidateTokenReader(r)
		assert.Error(err, "ValidateTokenReader should fail for token with invalid scope")

		r.Reset(t1)
		_, err = enf.ValidateTokenReader(r)
		assert.NoError(err, "ValidateTokenReader should succeed")
	})

	t.Run("validate token from form value", func(t *testing.T) {
		enf, err := NewEnforcer(ctx, ts.URL)
		if !assert.NoError(err, "NewEnforcer should succeed") {
			return
		}
		v := url.Values{}
		v.Add("token", string(nt1))
		_, err = enf.ValidateTokenForm(v, "token")
		assert.Error(err, "ValidateTokenForm should fail for invalid token")

		v.Set("token", string(nt2))
		_, err = enf.ValidateTokenForm(v, "token")
		assert.Error(err, "ValidateTokenForm should fail for token with invalid scope")

		v.Set("token", string(t1))
		_, err = enf.ValidateTokenForm(v, "token")
		assert.NoError(err, "ValidateTokenForm should succeed")
	})

	t.Run("validate token from header value", func(t *testing.T) {
		enf, err := NewEnforcer(ctx, ts.URL)
		if !assert.NoError(err, "NewEnforcer should succeed") {
			return
		}
		h := http.Header{}
		h.Add("X-SciToken", string(nt1))
		_, err = enf.ValidateTokenHeader(h, "X-SciToken")
		assert.Error(err, "ValidateTokenHeader should fail for invalid token")

		h.Set("X-SciToken", string(nt2))
		_, err = enf.ValidateTokenHeader(h, "X-SciToken")
		assert.Error(err, "ValidateTokenHeader should fail for token with invalid scope")

		h.Set("X-SciToken", string(t1))
		// For the header "Authorization", it will strip the prefix "Bearer "
		// and will treat the remaining value as a JWT.
		h.Add("Authorization", "Bearer "+string(t1))

		_, err = enf.ValidateTokenHeader(h, "X-SciToken")
		assert.NoError(err, "ValidateTokenHeader should succeed for X-SciToken header")

		_, err = enf.ValidateTokenHeader(h, "Authorization")
		assert.NoError(err, "ValidateTokenHeader should succeed for Authorization header")
	})

	t.Run("validate token from http request", func(t *testing.T) {
		enf, err := NewEnforcer(ctx, ts.URL)
		if !assert.NoError(err, "NewEnforcer should succeed") {
			return
		}
		r := httptest.NewRequest("GET", "https://example.com/foo", nil)
		r.Header.Add("Authorization", "Bearer "+string(nt1))
		_, err = enf.ValidateTokenRequest(r)
		assert.Error(err, "ValidateTokenRequest should fail for invalid token")

		r.Header.Set("Authorization", "Bearer "+string(nt2))
		_, err = enf.ValidateTokenRequest(r)
		assert.Error(err, "ValidateTokenRequest should fail for token with invalid scope")

		r.Header.Set("Authorization", "Bearer "+string(t1))
		_, err = enf.ValidateTokenRequest(r)
		assert.NoError(err, "ValidateTokenRequest should succeed")
	})

	t.Run("validate token from environment", func(t *testing.T) {
		enf, err := NewEnforcer(ctx, ts.URL)
		if !assert.NoError(err, "NewEnforcer should succeed") {
			return
		}

		resetEnv := clearEnv("BEARER_TOKEN", "BEARER_TOKEN_FILE", "XDG_RUNTIME_DIR", "TMPDIR")
		defer resetEnv()

		_, err = enf.ValidateTokenEnvironment()
		assert.ErrorIs(err, TokenNotFoundError, "ValidateTokenEnvironment should return TokenNotFoundError")

		if !assert.NoError(os.Setenv("BEARER_TOKEN", string(nt1))) {
			return
		}
		_, err = enf.ValidateTokenEnvironment()
		assert.Error(err, "ValidateTokenEnvironment should fail for invalid token")

		if !assert.NoError(os.Setenv("BEARER_TOKEN", string(nt2))) {
			return
		}
		_, err = enf.ValidateTokenEnvironment()
		assert.Error(err, "ValidateTokenEnvironment should fail for token with invalid scope")

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

package scitokens

import (
	"bytes"
	"testing"

	"github.com/lestrrat-go/jwx/jwt"
	"github.com/stretchr/testify/assert"
)

func TestPrintToken(t *testing.T) {
	assert := assert.New(t)
	var buf bytes.Buffer
	t1 := jwt.New()
	t1.Set("ver", "scitoken:1.0")
	t1.Set("jti", "my-id")
	t1.Set("sub", "my-subject")
	t1.Set("iss", "my-issuer")
	t1.Set("aud", []string{"my-audience"})
	t1.Set("foo", "bar")
	PrintToken(&buf, t1)
	ref := `Token version: scitoken:1.0, ID: my-id
Subject: my-subject
Issuer: my-issuer
Audience: [my-audience]
Issued at: 0001-01-01 00:00:00 +0000 UTC, Valid after: 0001-01-01 00:00:00 +0000 UTC, Expires at: 0001-01-01 00:00:00 +0000 UTC
Claims:
	ver: scitoken:1.0
	foo: bar
`
	assert.Equal(ref, buf.String())
}

func TestGetScopes(t *testing.T) {
	t.Run("no scopes", func(t *testing.T) {
		assert := assert.New(t)
		t1 := jwt.New()
		s, err := GetScopes(t1)
		if !assert.NoError(err, "GetScopes should succeed") {
			return
		}
		assert.Equal(s, []Scope{})
	})
	t.Run("good scopes", func(t *testing.T) {
		assert := assert.New(t)
		t1 := jwt.New()
		if !assert.NoError(t1.Set("scope", "storage.read:/foo compute.run"), "setting scope should succeed") {
			return
		}
		s, err := GetScopes(t1)
		if !assert.NoError(err, "GetScopes should succeed") {
			return
		}
		assert.Equal(s, []Scope{
			{"storage.read", "/foo"},
			{"compute.run", ""},
		})
	})
	t.Run("bad scopes", func(t *testing.T) {
		assert := assert.New(t)
		t1 := jwt.New()
		if !assert.NoError(t1.Set("scope", 0)) {
			return
		}
		_, err := GetScopes(t1)
		assert.Error(err, "GetScopes should fail")
	})
}

func TestGetGroups(t *testing.T) {
	t.Run("no groups", func(t *testing.T) {
		assert := assert.New(t)
		t1 := jwt.New()
		g, err := GetGroups(t1)
		if !assert.NoError(err, "GetGroups should succeed") {
			return
		}
		assert.Equal(g, []string{})
	})
	t.Run("good groups", func(t *testing.T) {
		assert := assert.New(t)
		t1 := jwt.New()
		if !assert.NoError(t1.Set("wlcg.groups", []interface{}{"/foo/bar", "/foo/baz"}), "setting groups should succeed") {
			return
		}
		g, err := GetGroups(t1)
		if !assert.NoError(err, "GetGroups should succeed") {
			return
		}
		assert.Equal(g, []string{"/foo/bar", "/foo/baz"})
	})
	t.Run("bad groups", func(t *testing.T) {
		assert := assert.New(t)
		t1 := jwt.New()
		if !assert.NoError(t1.Set("wlcg.groups", []string{"/foo/bar", "/foo/baz"}), "setting groups should succeed") {
			return
		}
		_, err := GetGroups(t1)
		assert.Error(err, "GetGroups should fail")
	})
	t.Run("bad group", func(t *testing.T) {
		assert := assert.New(t)
		t1 := jwt.New()
		if !assert.NoError(t1.Set("wlcg.groups", []interface{}{0, "/foo/baz"}), "setting groups should succeed") {
			return
		}
		_, err := GetGroups(t1)
		assert.Error(err, "GetGroups should fail")
	})
}

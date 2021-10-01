package scitokens

import (
	"testing"

	"github.com/lestrrat-go/jwx/jwt"
	"github.com/stretchr/testify/assert"
)

func TestNewSciToken(t *testing.T) {
	t.Run("Bare non-SciToken", func(t *testing.T) {
		assert := assert.New(t)
		t1 := jwt.New()
		st, err := NewSciToken(t1)
		if !assert.NoError(err, "NewSciToken should succeed") {
			return
		}
		if !assert.NotNil(st, "SciToken should not be nil") {
			return
		}
		assert.Equal(st.Scopes(), []Scope{})
		assert.Equal(st.Groups(), []string{})
		assert.Equal(st.Audience(), t1.Audience())
		assert.Equal(st.Expiration(), t1.Expiration())
		assert.Equal(st.IssuedAt(), t1.IssuedAt())
		assert.Equal(st.Issuer(), t1.Issuer())
		assert.Equal(st.JwtID(), t1.JwtID())
		assert.Equal(st.NotBefore(), t1.NotBefore())
		assert.Equal(st.Subject(), t1.Subject())
		assert.Equal(st.PrivateClaims(), t1.PrivateClaims())
		assert.NoError(st.Set("foo", "bar"))
		foo, ok := st.Get("foo")
		assert.Equal(foo, "bar")
		assert.True(ok, "claim foo should be set")
		assert.NoError(st.Remove("foo"))
		_, ok = st.Get("foo")
		assert.False(ok, "claim foo should not be set after Remove()")
		st2, err := st.Clone()
		if !assert.NoError(err, "Clone() should succeed") {
			return
		}
		assert.Equal(st, st2)
	})
	t.Run("SciToken with scope and groups", func(t *testing.T) {
		assert := assert.New(t)
		t1 := jwt.New()
		if !assert.NoError(t1.Set("scope", "storage.read:/foo compute.run"), "setting scope should succeed") {
			return
		}
		if !assert.NoError(t1.Set("wlcg.groups", []interface{}{"/foo/bar", "/foo/baz"}), "setting groups should succeed") {
			return
		}
		st, err := NewSciToken(t1)
		if !assert.NoError(err, "NewSciToken should succeed") {
			return
		}
		if !assert.NotNil(st, "SciToken should not be nil") {
			return
		}
		assert.Equal(st.Scopes(), []Scope{
			{"storage.read", "/foo"},
			{"compute.run", ""},
		})
		assert.Equal(st.Groups(), []string{"/foo/bar", "/foo/baz"})
	})
	t.Run("SciToken with invalid scope", func(t *testing.T) {
		assert := assert.New(t)
		t1 := jwt.New()
		if !assert.NoError(t1.Set("scope", []interface{}{"foo", "bar"}), "setting scope should succeed") {
			return
		}
		_, err := NewSciToken(t1)
		assert.Error(err, "NewSciToken should fail")
	})
	t.Run("SciToken with invalid groups", func(t *testing.T) {
		assert := assert.New(t)
		t1 := jwt.New()
		if !assert.NoError(t1.Set("wlcg.groups", "foo,bar"), "setting groups should succeed") {
			return
		}
		_, err := NewSciToken(t1)
		assert.Error(err, "NewSciToken should fail")
	})
}

package scitokens

import (
	"context"
	"testing"

	"github.com/lestrrat-go/jwx/jwt"
	"github.com/stretchr/testify/assert"
)

func TestScopeValidator(t *testing.T) {
	assert := assert.New(t)
	ctx := context.Background()

	t1 := jwt.New()
	t1.Set("scope", "read:/foo write:/foo/bar")
	st1, err := NewSciToken(t1)
	if !assert.NoError(err) {
		return
	}

	v := WithScope(Scope{"read", "/foo"})
	assert.ErrorIs(v.Validate(ctx, t1), NotSciTokenError, "cannot validate non-SciToken")
	assert.NoError(v.Validate(ctx, st1), "token has read permission on /foo")

	v = WithScope(Scope{"read", "/foo/bar"})
	assert.NoError(v.Validate(ctx, st1), "sub-paths can be read")

	v = WithScope(Scope{"read", "/qux"})
	assert.Error(v.Validate(ctx, st1), "token does not have read permission on /qux")

	v = WithScope(Scope{"write", "/foo"})
	assert.Error(v.Validate(ctx, st1), "token does not have write permission on /foo")

	v = WithScope(Scope{"write", "/foo/bar"})
	assert.NoError(v.Validate(ctx, st1), "token has write permission on /foo/bar")

	v = WithScope(Scope{"write", "/foo/bar/baz"})
	assert.NoError(v.Validate(ctx, st1), "sub-paths can be written")

	v = WithScope(Scope{"compute", ""})
	assert.Error(v.Validate(ctx, st1), "token does not have compute permission")
}

func TestGroupValidator(t *testing.T) {
	assert := assert.New(t)
	ctx := context.Background()

	t1 := jwt.New()
	t1.Set("wlcg.groups", []interface{}{"/foo"})
	st1, err := NewSciToken(t1)
	if !assert.NoError(err) {
		return
	}

	v := WithGroup("/foo")
	assert.ErrorIs(v.Validate(ctx, t1), NotSciTokenError, "cannot validate non-SciToken")
	assert.NoError(v.Validate(ctx, st1), "token has group foo")

	v = WithGroup("foo")
	assert.NoError(v.Validate(ctx, st1), "leading slash is optional")

	v = WithGroup("bar")
	assert.Error(v.Validate(ctx, st1), "token does not have group bar")

	v = WithGroup("foo/bar")
	assert.Error(v.Validate(ctx, st1), "token does not have sub-group foo/bar")
}

func TestAudienceValidator(t *testing.T) {
	assert := assert.New(t)
	ctx := context.Background()

	t1 := jwt.New()
	t1.Set("ver", "scitoken:2.0")
	t1.Set("aud", "foo")
	st1, err := NewSciToken(t1)
	if !assert.NoError(err) {
		return
	}

	v := WithAudience("bar")
	assert.ErrorIs(v.Validate(ctx, t1), NotSciTokenError, "cannot validate non-SciToken")
	assert.Error(v.Validate(ctx, st1), "token does not have required audience")

	assert.NoError(t1.Set("aud", "bar"))
	assert.NoError(v.Validate(ctx, st1), "token has required audience")

	assert.NoError(st1.Remove("aud"))
	assert.Error(v.Validate(ctx, st1), "audience is mandatory for scitoken v2.0")
	assert.NoError(st1.Set("ver", "scitoken:1.0"))
	assert.NoError(v.Validate(ctx, st1), "audience is not mandatory for scitoken v1.0")

	assert.NoError(st1.Set("ver", "scitoken:2.0"))
	for _, any := range AnyAudiences {
		assert.NoError(st1.Set("aud", any))
		assert.NoErrorf(v.Validate(ctx, st1), "%s audience allows use for any audience", any)
	}
}

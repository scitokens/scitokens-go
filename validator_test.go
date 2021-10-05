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
	t1.Set("scope", "read:/foo")
	st1, err := NewSciToken(t1)
	if !assert.NoError(err) {
		return
	}

	v := WithScope(Scope{"read", "/foo"})
	assert.Error(v.Validate(ctx, t1), "cannot validate non-SciToken")
	assert.NoError(v.Validate(ctx, st1), "token has read permission on /foo")

	v = WithScope(Scope{"read", "/"})
	assert.Error(v.Validate(ctx, st1), "token does not have read permission on /")

	v = WithScope(Scope{"read", "/bar"})
	assert.Error(v.Validate(ctx, st1), "token does not have read permission on /bar")

	v = WithScope(Scope{"write", "/foo"})
	assert.Error(v.Validate(ctx, st1), "token does not have write permission on /foo")

	v = WithScope(Scope{"compute", ""})
	assert.Error(v.Validate(ctx, st1), "token does not have compute permission")
}

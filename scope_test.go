package scitokens

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestScope(t *testing.T) {
	assert := assert.New(t)
	s := ParseScope("foo:/bar:baz")
	assert.Equal(s.Auth, "foo")
	assert.Equal(s.Path, "/bar:baz", "anything after colon is path")

	s = ParseScope("foo:/foo/../bar")
	assert.Equal(s.Auth, "foo")
	assert.Equal(s.Path, "/bar", "paths are normalized")

	assert.Equal(s.String(), "foo:/bar")

	assert.True(s.Allowed("foo", "/bar"), "scope allows access to own path")
	assert.True(s.Allowed("foo", "/bar/baz"), "scope allows access to sub-path")
	assert.False(s.Allowed("foo", "/bar/.."), "resource paths are normalized")
	assert.True(s.Allowed("foo", "///foo/../bar"), "resource paths are normalized (2)")

	s = ParseScope("foo")
	assert.True(s.Allowed("foo", "/qux"), "scope without path allows access to any resource path")
	assert.Equal(s.String(), "foo")
}

package scitokens

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidationError(t *testing.T) {
	assert := assert.New(t)
	err1 := errors.New("oops")
	err2 := &TokenValidationError{err1}
	assert.Equal("token invalid: oops", err2.Error())
	assert.ErrorIs(err2, err1)
}

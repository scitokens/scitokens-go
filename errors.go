package scitokens

import (
	"fmt"
)

type NotFoundError struct{}

func (e NotFoundError) Error() string {
	return "404 not found"
}

type TokenParseError struct {
	Err error
}

func (t *TokenParseError) Error() string {
	return fmt.Sprintf("error while parsing token: %s", t.Err)
}

type TokenValidationError struct {
	Err error
}

func (t *TokenValidationError) Error() string {
	return fmt.Sprintf("token invalid: %s", t.Err)
}

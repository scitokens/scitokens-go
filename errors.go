package scitokens

import (
	"errors"
	"fmt"
)

var (
	MetadataNotFoundError  = errors.New("metadata not found")
	IKMNotInitializedError = errors.New("IssuerKeyManager not initialized")
	UntrustedIssuerError   = errors.New("issuer not trusted")
	NotSciTokenError       = errors.New("token is not a SciToken")
)

type TokenParseError struct {
	Err error
}

func (e *TokenParseError) Error() string {
	return fmt.Sprintf("error while parsing token: %s", e.Err)
}

func (e *TokenParseError) Unwrap() error {
	return e.Err
}

type TokenValidationError struct {
	Err error
}

func (e *TokenValidationError) Error() string {
	return fmt.Sprintf("token invalid: %s", e.Err)
}

func (e *TokenValidationError) Unwrap() error {
	return e.Err
}

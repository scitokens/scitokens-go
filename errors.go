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
	TokenNotFoundError     = errors.New("token not found")
	ScopeParseError        = errors.New("unable to unmarshal and parse scope claim")
	GroupParseError        = errors.New("unable to unmarshal wlcg.groups claim")
	VersionParseError      = errors.New("unable to unmarshal ver claim")
)

type TokenValidationError struct {
	Err error
}

func (e *TokenValidationError) Error() string {
	return fmt.Sprintf("token invalid: %s", e.Err)
}

func (e *TokenValidationError) Unwrap() error {
	return e.Err
}

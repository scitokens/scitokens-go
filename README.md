# scitokens-go [![Go Reference](https://pkg.go.dev/badge/github.com/scitokens/scitokens-go.svg)](https://pkg.go.dev/github.com/scitokens/scitokens-go)

**WORK IN PROGRESS** library for handling [SciTokens](https://scitokens.org)
from Go, based on
[github.com/lestrrat-go/jwx](https://github.com/lestrrat-go/jwx) libraries.
Included is a `scitoken-validate` command-line tool that uses the library to
validate SciTokens with various criteria.

The Enforcer API is believed to be stable, but breaking changes may still occur
until version 1.0.0 is released. 

## Usage

To fetch and add the library to your Go project dependencies, run:

    go get github.com/scitokens/scitokens-go

### Parsing SciTokens

Note: if you're only interested in validating tokens in a service, you can skip
to the next section [Validating Tokens](#validating-tokens), since the Enforcer
abstracts away these details.

The [`SciToken`](https://pkg.go.dev/github.com/scitokens/scitokens-go#SciToken)
interface is a light wrapper around the general `Token` interface from the
[`github.com/lestrrat-go/jwx/jwt`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwt)
package, providing convenience methods for parsing and accessing
SciToken-specific claims. After parsing the token into a
[`jwt.Token`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwt#Token) you can
convert it to an object implementing the `SciToken` interface with
[`NewSciToken()`](https://pkg.go.dev/github.com/scitokens/scitokens-go#NewSciToken).

``` go
// PrintSciToken prints SciToken information to stdout, without doing any
// verification or validation of the token or its claims.
func PrintSciToken(tok []byte) error {
	jt, err := jwt.Parse(tok)
	if err != nil {
		return err
	}
	st, err := NewSciToken(jt)
	if err != nil {
		return err
	}
	fmt.Println(st.Subject())
	fmt.Println(st.Issuer())
	fmt.Println(st.Scopes())
	fmt.Println(st.Groups())
	return nil
}
```

### Validating Tokens

The [`Enforcer`](https://pkg.go.dev/github.com/scitokens/scitokens-go#Enforcer)
object is used to verify and validate tokens. Instantiate it with
[`NewEnforcer()`](https://pkg.go.dev/github.com/scitokens/scitokens-go#NewEnforcer),
passing a context that defines the lifetime of the Enforcer and one or more
supported issuer URLs.

``` go
ctx, cancel := context.WithCancel(context.Background())
defer cancel()
enf, err := scitokens.NewEnforcer(ctx, "https://example.com")
if err != nil {
	log.Fatalf("failed to initialize enforcer: %s", err)
}
```

In the background the Enforcer will fetch and cache the signing keys from the
issuer, and start a goroutine that will routinely refresh the keys (for
long-lived processes). Additional issuers can be added later with
[`AddIssuer()`](https://pkg.go.dev/github.com/scitokens/scitokens-go#Enforcer.AddIssuer).

The enforcer provides a
[`ValidateToken()`](https://pkg.go.dev/github.com/scitokens/scitokens-go#Enforcer.ValidateToken)
method that verifies and validates a raw encoded token, and several convenience
methods for validating tokens from a number of sources, including HTTP requests
([`ValidateTokenRequest()`](https://pkg.go.dev/github.com/scitokens/scitokens-go#Enforcer.ValidateTokenRequest)),
and the execution environment
([`ValidateTokenEnvironment()`](https://pkg.go.dev/github.com/scitokens/scitokens-go#Enforcer.ValidateTokenEnvironment)).

By default the enforcer will verify that the token was signed by a trusted
issuer, and that it passes basic validation criteria such as dates. It is not
possible to directly parse a SciToken without performing these basic validation
checks, this is by design, although it could change in the future if there is a
good use case (the `ValidateToken...` function signatures and behavior won't
change though).

Additional validation criteria can be attached to the enforcer with the
[`RequireScope()`](https://pkg.go.dev/github.com/scitokens/scitokens-go#Enforcer.RequireScope)
and
[`RequireGroup()`](https://pkg.go.dev/github.com/scitokens/scitokens-go#Enforcer.RequireGroup)
methods, which take a
[`Scope`](https://pkg.go.dev/github.com/scitokens/scitokens-go#Scope) object
that the token must have in the `scope` claim (pathed scopes will match exactly
or for a hierarchical parent) and a group name that must be in the `wlcg.groups`
claim (group name must match exactly, but leading slash is optional),
respectively.

``` go
if err := enf.RequireScope(scitokens.Scope{"compute.read", ""}); err != nil {
	log.Fatal(err)
}
if err := enf.RequireGroup("cms"); err != nil {
	log.Fatal(err)
}
```

Criteria set this way will apply to all future `ValidateToken...` calls. It's
also possible to pass additional request-specific validation criteria to the
`ValidateToken...` functions.

``` go
if _, err := enf.ValidateToken(tok, scitokens.WithGroup("cms/production")); err != nil {
	e := &scitokens.TokenValidationError{}
	if !errors.As(err, &e) {
		// some internal error while parsing/validating the token
		log.Error(err)
	} else {
		// token is not valid, err (and e.Err) will say why.
		log.Debugf("access dened: %v", err)
	}
	denyRequest(err)
} else {
	doRequest()
}
```

This example also demonstrates using `errors.As()` to check if the returned
error is specifically a `TokenValidationError` due to the token not meeting some
criteria, or some other internal error, which you may want to handle
differently.

The `ValidateToken...` functions return a `SciToken` that can be inspected
directly or passed to
[`Validate()`](https://pkg.go.dev/github.com/scitokens/scitokens-go#Enforcer.Validate)
to test different criteria.

``` go
if st, err := enf.ValidateToken(tok, scitokens.WithGroup("cms/production")); err != nil {
	if enf.Validate(st, scitokens.WithGroup("cms/operations")) {
		doRequest()
	}
	denyRequest(err)
} else {
	doRequest()
}
```

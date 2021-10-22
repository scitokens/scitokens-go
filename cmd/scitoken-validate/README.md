# scitoken-validate: Basic SciToken validator.

The SciToken will be read from a file pointed to by the SCITOKEN environment
variable, or if undefined from a file named like /tmp/scitoken_u$UID, otherwise
read from stdin. Currently only one token is expected to be in the file.

At least one token issuer must be specified with the --issuer/-i flag, which can
be repeated. Signing keys will be fetched for each issuer to validate the tokens
signature, and it will also be validated that the token was issued by one of them.

Optionally pass one or more audiences to require with the --audience/-a flag.
This will also validate if the token has one of the special "any" audiences.

Optionally pass one or more scopes to validate with the --scope/-s flag. Note that
scope paths will validate sub-paths (see example).

Optionally pass one or more WLCG groups to require with the --group/-g flag. Note
that groups WILL NOT validate sub-groups (see example).

If the token is not valid an explanation message will be printed to stderr and
the program will terminate with exit code 1.

## INSTALLATION

With [Go compiler and tools](https://golang.org) installed, run:

    go install github.com/scitokens/scitokens-go/cmd/scitoken-validate@latest

This will fetch, compile, and install the binary in `$GOPATH/bin` or
`$HOME/go/bin` if `$GOPATH` is not set.

## EXAMPLES

Basic validation:

    scitoken-validate -i https://cilogon.org/fermilab

Enforce scopes:

    scitoken-validate -i https://cilogon.org/fermilab -s compute.create -s storage.read:/fermilab/users/kretzke/foo

Note that scope paths will validate sub-paths, e.g. this will validate a
token that has storage.read:/fermilab/users/kretzke.

Enforce groups:

    scitoken-validate -i https://cilogon.org/fermilab -g nova/production

Note that groups WILL NOT validate sub-groups, e.g. this will NOT validate a
token that only has "/nova".

## FLAGS

``` 
  -a, --audience strings   audience to validate (or any). Can be repeated.
  -g, --group strings      WLCG group to validate. The leading slash on the group name is optional. Can be repeated.
  -i, --issuer strings     trusted token issuer for obtaining keys and validating token. Can be repeated.
  -s, --scope strings      scope to validate, with optional path delimited by colon. Can be repeated.
  -v, --verbose            extra logging of token information and internals to stderr.
```

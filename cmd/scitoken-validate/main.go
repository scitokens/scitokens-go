package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"

	scitoken "github.com/scitokens/scitokens-go"
	flag "github.com/spf13/pflag"
)

var (
	issuers *[]string = flag.StringSliceP("issuer", "i", []string{},
		"trusted token issuer for obtaining keys and validating token. Can be repeated.")
	scopes *[]string = flag.StringSliceP("scope", "s", []string{},
		"scope to validate, with optional path delimited by colon. Can be repeated.")
	groups *[]string = flag.StringSliceP("group", "g", []string{},
		"WLCG group to validate. The leading slash on the group name is optional. Can be repeated.")
	audiences *[]string = flag.StringSliceP("audience", "a", []string{},
		"audience to validate (or any). Can be repeated.")
	verbose *bool = flag.BoolP("verbose", "v", false,
		"extra logging of token information and internals to stderr.")
)

func init() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s: Basic SciToken validator.\n", os.Args[0])
		fmt.Fprintf(os.Stderr, `
The SciToken will be read from the environment per https://doi.org/10.5281/zenodo.3937438,
otherwise read from stdin. Currently only one token is expected to be in the file.

At least one token issuer must be specified with the --issuer/-i flag, which can
be repeated. Signing keys will be fetched for each issuer to validate the tokens
signature, and it will also be validated that the token was issued by one of them.

Optionally pass one or more scopes to validate with the --scope/-s flag. Note that
scope paths will validate sub-paths (see example).

Optionally pass one or more WLCG groups to require with the --group/-g flag. Note
that groups WILL NOT validate sub-groups (see example).

Optionally pass one or more audiences to require with the --audience/-a flag.
This will also validate if the token has one of the special "any" audiences.

If the token is not valid an explanation message will be printed to stderr and
the program will terminate with exit code 1.

EXAMPLES

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

FLAGS
`)
		flag.PrintDefaults()
	}
	flag.Parse()
}

func main() {
	// The Enforcer has some background processes, so we need a context to tell
	// it to clean up before exiting.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	enf, err := scitoken.NewEnforcer(ctx, *issuers...)
	if err != nil {
		log.Fatalf("failed to initialize enforcer: %s", err)
	}

	// Validation constraints can be added to the base Enforcer...
	for _, s := range *scopes {
		enf.RequireScope(scitoken.ParseScope(s))
	}
	for _, a := range *audiences {
		enf.RequireAudience(a)
	}

	// ... or added on at parse time.
	validators := make([]scitoken.Validator, len(*groups))
	for i, g := range *groups {
		validators[i] = scitoken.WithGroup(g)
	}

	// Read in the token from the environment or stdin, and parse and validate
	// it at the same time. It can also be validated against additional
	// constraints by calling scitoken.Validate().
	tok, err := enf.ValidateTokenEnvironment(validators...)
	if errors.Is(err, scitoken.TokenNotFoundError) {
		log.Printf("no token found in environment, reading from stdin")
		tok, err = enf.ValidateTokenReader(os.Stdin, validators...)
	}

	if *verbose && tok != nil {
		scitoken.PrintToken(os.Stderr, tok)
	}
	if err != nil {
		log.Fatal(err)
	}
}

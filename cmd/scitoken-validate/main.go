package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"

	scitoken "github.com/retzkek/scitokens-go"
	flag "github.com/spf13/pflag"
)

var (
	issuers *[]string = flag.StringSliceP("issuer", "i", []string{},
		"trusted token issuer for obtaining keys and validating token. Can be repeated.")
	scopes *[]string = flag.StringSliceP("scope", "s", []string{},
		"scope to validate, with optional path delimited by colon. Can be repeated.")
	groups *[]string = flag.StringSliceP("group", "g", []string{},
		"WLCG group to validate. The leading slash on the group name is optional. Can be repeated.")
	verbose *bool = flag.BoolP("verbose", "v", false,
		"extra logging of token information and internals to stderr.")
)

func init() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s: Basic SciToken validator.\n", os.Args[0])
		fmt.Fprintf(os.Stderr, `
The SciToken will be read from a file pointed to by the SCITOKEN environment
variable, or if undefined from a file named like /tmp/scitoken_u$UID, otherwise
read from stdin. Currently only one token is expected to be in the file.

At least one token issuer must be specified with the --issuer/-i flag, which can
be repeated. Signing keys will be fetched for each issuer to validate the tokens
signature, and it will also be validated that the token was issued by one of them.

Optionally pass one or more scopes to validate with the --scope/-s flag. Note that
scope paths will validate sub-paths (see example).

Optionally pass one or more WLCG groups to require with the --group/-g flag. Note
that groups WILL NOT validate sub-groups (see example).

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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	enf, err := scitoken.NewEnforcer(ctx, *issuers...)
	if err != nil {
		log.Fatalf("failed to initialize enforcer: %s", err)
	}
	for _, s := range *scopes {
		if err = enf.RequireScope(scitoken.ParseScope(s)); err != nil {
			log.Fatalf("unable to require scope %s: %s", s, err)
		}
	}
	for _, g := range *groups {
		if err = enf.RequireGroup(g); err != nil {
			log.Fatalf("unable to require group %s: %s", g, err)
		}
	}

	filename := os.Getenv("SCITOKEN")
	if filename == "" {
		filename = fmt.Sprintf("/tmp/scitoken_u%d", os.Getuid())
		if _, err := os.Stat(filename); err != nil {
			filename = ""
		}
	}
	var t io.Reader
	if filename != "" {
		log.Printf("reading token from file %s", filename)
		f, err := os.Open(filename)
		if err != nil {
			log.Fatalf("error opening token file %s", filename)
		}
		defer f.Close()
		t = f
	} else {
		log.Printf("reading token from stdin")
		t = os.Stdin
	}
	tok, err := enf.ValidateTokenReader(t)
	if *verbose && tok != nil {
		scitoken.PrintToken(os.Stderr, tok)
	}
	if err != nil {
		log.Fatalf("token not valid: %s", err)
	}
}

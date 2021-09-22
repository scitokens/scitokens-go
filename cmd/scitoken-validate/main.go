package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	scitokens "github.com/retzkek/scitokens-go"
	flag "github.com/spf13/pflag"
)

var (
	issuer *string = flag.StringP("issuer", "i", "https://cilogon.org/fermilab",
		"token issuer, used for obtaining keys and validating token")
	scopes *[]string = flag.StringSliceP("scope", "s", []string{},
		"scope to validate, with optional path delimited by colon. Can be repeated")
	verbose *bool = flag.BoolP("verbose", "v", false,
		"extra logging of token information and internals to stderr")
)

func init() {
	flag.Parse()
}

func main() {
	enf, err := scitokens.NewEnforcer(*issuer)
	if err != nil {
		log.Fatalf("failed to initialize enforcer: %s\n", err)
	}
	if *verbose {
		enf.SetLogger(os.Stderr)
	}
	for _, s := range *scopes {
		pts := strings.SplitN(s, ":", 2)
		if err = enf.RequireScope(pts[0], pts[1:]...); err != nil {
			log.Fatalf("unable to require scope %s: %s\n", s, err)
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
	err = enf.ValidateTokenReader(t)
	if err != nil {
		log.Fatalf("token not valid: %s\n", err)
	}
}

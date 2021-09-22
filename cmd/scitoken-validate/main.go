package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	scitokens "github.com/retzkek/scitokens-go"
)

var (
	issuer *string = flag.String("issuer", "https://cilogon.org/fermilab",
		"token issuer, used for obtaining keys and validating token")
)

func init() {
	flag.Parse()
}

func main() {
	enf, err := scitokens.NewEnforcer(*issuer)
	if err != nil {
		log.Fatalf("failed to initialize enforcer: %s\n", err)
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

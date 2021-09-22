package scitokens

import (
	"fmt"
	"io"

	"github.com/lestrrat-go/jwx/jwt"
)

func printToken(t jwt.Token, w io.Writer) {
	fmt.Fprintf(w, "Subject: %s\n", t.Subject())
	fmt.Fprintf(w, "Issuer: %s\n", t.Issuer())
	fmt.Fprintf(w, "Audience: %s\n", t.Audience())
	fmt.Fprintf(w, "Issued at: %s, Expires at: %s\n", t.IssuedAt(), t.Expiration())
	fmt.Fprintf(w, "Claims: %v\n", t.PrivateClaims())
}

package scitokens

import (
	"fmt"

	"github.com/lestrrat-go/jwx/jwt"
)

func printToken(t jwt.Token) {
	fmt.Printf("Subject: %s\n", t.Subject())
	fmt.Printf("Issuer: %s\n", t.Issuer())
	fmt.Printf("Audience: %s\n", t.Audience())
	fmt.Printf("Issued at: %s, Expires at: %s\n", t.IssuedAt(), t.Expiration())
	fmt.Printf("Claims: %v", t.PrivateClaims())
}

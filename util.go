package scitokens

import (
	"fmt"
	"io"
	"strings"

	"github.com/lestrrat-go/jwx/jwt"
)

// PrintToken pretty-prints the token claims to w.
func PrintToken(w io.Writer, t jwt.Token) {
	ver, _ := GetVersion(t)
	fmt.Fprintf(w, "Token version: %s, ID: %s\n", ver, t.JwtID())
	fmt.Fprintf(w, "Subject: %s\n", t.Subject())
	fmt.Fprintf(w, "Issuer: %s\n", t.Issuer())
	fmt.Fprintf(w, "Audience: %s\n", t.Audience())
	fmt.Fprintf(w, "Issued at: %s, Valid after: %s, Expires at: %s\n", t.IssuedAt(), t.NotBefore(), t.Expiration())
	fmt.Fprintf(w, "Claims:\n")
	for k, v := range t.PrivateClaims() {
		fmt.Fprintf(w, "\t%v: %v\n", k, v)
	}
}

// GetScopes parses the scope claim and returns a list of all scopes, or an
// empty list if the scope claim is missing.
//
// Returns ScopeParseError if the scope claim cannot be unmarshaled or parsed.
func GetScopes(t jwt.Token) ([]Scope, error) {
	scopeint, ok := t.Get("scope")
	if !ok {
		return []Scope{}, nil
	}
	scopestr, ok := scopeint.(string)
	if !ok {
		return nil, ScopeParseError
	}
	scopestrs := strings.Split(scopestr, " ")
	scopes := make([]Scope, len(scopestrs))
	for i, s := range scopestrs {
		scopes[i] = ParseScope(s)
	}
	return scopes, nil
}

// GetGroups parses the wlcg.groups claim and returns a list of all groups, or
// an empty list if the wlcg.groups claim is missing.
//
// Returns GroupParseError if the wlcg.groups claim cannot be unmarshaled.
func GetGroups(t jwt.Token) ([]string, error) {
	groupint, ok := t.Get("wlcg.groups")
	if !ok {
		return []string{}, nil
	}
	groupints, ok := groupint.([]interface{})
	if !ok {
		return nil, GroupParseError
	}
	groups := make([]string, len(groupints))
	for i, g := range groupints {
		gs, ok := g.(string)
		if !ok {
			return nil, GroupParseError
		}
		groups[i] = gs
	}
	return groups, nil
}

// GetVersion retrieves the ver claim, or an empty string if the claim is
// missing. For compatability it will also look for the wlcg.ver claim, which
// will be returned as "wlcg:$ver", where $ver is the value of the claim.
func GetVersion(t jwt.Token) (string, error) {
	profile := ""
	verint, ok := t.Get("ver")
	if !ok {
		profile = "wlcg"
		verint, ok = t.Get("wlcg.ver")
		if !ok {
			return "", nil
		}
	}
	ver, ok := verint.(string)
	if !ok {
		return "", VersionParseError
	}
	if profile != "" {
		ver = profile + ":" + ver
	}
	return ver, nil
}

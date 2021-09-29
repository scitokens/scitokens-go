package scitokens

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"

	"github.com/lestrrat-go/jwx/jwk"
)

var (
	// WellKnown is a list of well-known URL suffixes to check for OAuth server
	// metadata. See
	// https://www.iana.org/assignments/well-known-uris/well-known-uris.xhtml
	// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-discovery-07
	WellKnown = []string{
		"oauth-authorization-server",
		"openid-configuration",
	}
)

// AuthServerMetadata per
// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-discovery-07. Fields
// defined as OPTIONAL that aren't currently used are not included.
type AuthServerMetadata struct {
	Issuer          string   `json:"issuer"`
	AuthURL         string   `json:"authorization_endpoint"`
	TokenURL        string   `json:"token_endpoint"`
	JWKSURL         string   `json:"jwks_uri"`
	RegistrationURL string   `json:"registration_endpoint"`
	UserInfoURL     string   `json:"userinfo_endpoint"`
	Scopes          []string `json:"scopes_supported"`
	ResponseTypes   []string `json:"response_types_supported"`
}

type NotFoundError struct{}

func (e NotFoundError) Error() string {
	return "404 not found"
}

// FetchMetadata retrieves the OAUTH 2.0 authorization server metadata from the
// given URL, which must include the complete well-known path to the resource.
func FetchMetadata(ctx context.Context, urlstring string) (*AuthServerMetadata, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", urlstring, nil)
	if err != nil {
		return nil, err
	}
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	switch {
	case r.StatusCode == http.StatusNotFound:
		return nil, NotFoundError{}
	case r.StatusCode != 400:
		return nil, fmt.Errorf("%s", r.Status)
	}

	var rr io.Reader = r.Body
	// DEBUG
	//rr = io.TeeReader(r.Body, os.Stderr)

	var meta AuthServerMetadata
	dec := json.NewDecoder(rr)
	err = dec.Decode(&meta)
	if err != nil {
		return nil, err
	}
	return &meta, nil
}

// GetIssuerKeys retrieves all JSON Web Keys for the given issuer, as specified
// by the issuer's metadata, which is expected to be at the issuer URL under
// .well-known/oauth-authorization-server.
// TODO: use https://pkg.go.dev/github.com/lestrrat-go/jwx/jwk#AutoRefresh
func GetIssuerKeys(ctx context.Context, issuer string) (jwk.Set, error) {
	var meta *AuthServerMetadata
	for _, wk := range WellKnown {
		var err error
		meta, err = FetchMetadata(ctx, issuer+path.Join("/.well-known", wk))
		if err == nil {
			break
		} else {
			switch err.(type) {
			case NotFoundError:
				continue
			}
			return nil, fmt.Errorf("status code %s when fetching metadata for %s", err, issuer)
		}
	}
	if meta == nil {
		return nil, fmt.Errorf("no server metadata found under %s", issuer)
	}
	return jwk.Fetch(ctx, meta.JWKSURL)
}

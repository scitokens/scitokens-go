package issuer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
)

var (
	MetadataNotFoundError = errors.New("metadata not found")
)

// WellKnown is a list of well-known URL suffixes to check for OAuth server
// metadata. See
// https://www.iana.org/assignments/well-known-uris/well-known-uris.xhtml
// and
// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-discovery-07
var WellKnown = []string{
	"oauth-authorization-server",
	"openid-configuration",
}

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
		return nil, MetadataNotFoundError
	case r.StatusCode >= 400:
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

// KeyURL determines the URL for JWKS keys for the issuer, based on its
// OAuth metadata.
func KeyURL(ctx context.Context, issuer string) (string, error) {
	var meta *AuthServerMetadata
	for _, wk := range WellKnown {
		var err error
		meta, err = FetchMetadata(ctx, issuer+path.Join("/.well-known", wk))
		if err == nil {
			break
		} else if errors.Is(err, MetadataNotFoundError) {
			continue
		} else {
			return "", fmt.Errorf("fetching metadata for %s: %w", issuer, err)
		}
	}
	if meta == nil {
		return "", fmt.Errorf("no server metadata found under %s", issuer)
	}
	return meta.JWKSURL, nil
}

package internal

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"text/template"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

var (
	testMetadataTemplate = `{
  "issuer": "https://{{.Host}}/",
  "authorization_endpoint": "https://{{.Host}}/authorize",
  "token_endpoint": "https://{{.Host}}/token",
  "jwks_uri": "https://{{.Host}}/jwk",
  "registration_endpoint": "https://{{.Host}}/register",
  "userinfo_endpoint": "https://{{.Host}}/userinfo",
  "scopes_supported": [
    "openid",
    "profile",
    "email",
    "offline_access",
    "wlcg",
    "wlcg.groups",
    "storage.read:/",
    "storage.create:/",
    "compute.read",
    "compute.modify",
    "compute.create",
    "compute.cancel",
    "storage.modify:/",
    "eduperson_scoped_affiliation",
    "eduperson_entitlement"
  ],
  "response_types_supported": [
    "code",
    "token"
  ]
}`
)

type fakeAuthServer struct {
	privateKey jwk.Key
	publicKeys jwk.Set
	metadata   *template.Template
}

func NewFakeAuthServer() (*fakeAuthServer, error) {
	raw, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	k, err := jwk.New(raw)
	if err != nil {
		return nil, err
	}
	if k.Set("kid", "testkey1") != nil {
		return nil, err
	}
	ks := jwk.NewSet()
	pk, err := k.PublicKey()
	if err != nil {
		return nil, err
	}
	ks.Add(pk)

	t, err := template.New("metadata").Parse(testMetadataTemplate)
	if err != nil {
		return nil, err
	}

	return &fakeAuthServer{k, ks, t}, nil

}

func (s *fakeAuthServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.well-known/oauth-authorization-server",
		"/.well-known/openid-configuration":
		if err := s.metadata.Execute(w, r); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	case "/bad-metadata":
		fmt.Fprintln(w, "{foo:bar}")
	case "/jwk":
		enc := json.NewEncoder(w)
		enc.Encode(s.publicKeys)
	case "/private":
		http.Error(w, "forbidden", http.StatusForbidden)
	case "/error":
		http.Error(w, "error", http.StatusInternalServerError)
	default:
		http.Error(w, "bad path", http.StatusNotFound)
	}
}

// MakeToken creates and signs a test token with the given scopes and groups.
func (s *fakeAuthServer) MakeToken(issuer string, scopes, groups, audience interface{}) ([]byte, error) {
	t := jwt.New()
	t.Set("iss", issuer)
	t.Set("iat", time.Now())
	t.Set("nbf", time.Now())
	t.Set("exp", time.Now().Add(1*time.Hour))
	if scopes != nil {
		if err := t.Set("scope", scopes); err != nil {
			return nil, err
		}
	}
	if groups != nil {
		if err := t.Set("wlcg.groups", groups); err != nil {
			return nil, err
		}
	}
	if audience != nil {
		if err := t.Set("aud", audience); err != nil {
			return nil, err
		}
	}
	return jwt.Sign(t, jwa.RS256, s.privateKey)
}

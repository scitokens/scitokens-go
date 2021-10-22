package scitokens

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path"
	"testing"
	"text/template"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/stretchr/testify/assert"
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

func newFakeAuthServer() (*fakeAuthServer, error) {
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

func TestFetchMetadata(t *testing.T) {
	assert := assert.New(t)
	srv, err := newFakeAuthServer()
	if !assert.NoError(err) {
		return
	}
	ts := httptest.NewTLSServer(srv)
	defer ts.Close()
	http.DefaultClient = ts.Client()

	t.Run("nil context", func(t *testing.T) {
		_, err := FetchMetadata(nil, "https://example.com")
		assert.Error(err, "FetchMetadata should fail")
	})

	t.Run("bad metadata URL", func(t *testing.T) {
		_, err := FetchMetadata(context.Background(), "foo://bar/baz")
		assert.Error(err, "FetchMetadata should fail")
	})

	t.Run("missing metadata suffix", func(t *testing.T) {
		_, err := FetchMetadata(context.Background(), ts.URL+"/.well-known/does-not-exit")
		if !assert.Error(err, "FetchMetadata should fail") {
			return
		}
		assert.ErrorIs(err, MetadataNotFoundError)
	})

	t.Run("forbidden metadata server response", func(t *testing.T) {
		_, err := FetchMetadata(context.Background(), ts.URL+"/private")
		assert.Error(err, "FetchMetadata should fail")
	})

	t.Run("error metadata server response", func(t *testing.T) {
		_, err := FetchMetadata(context.Background(), ts.URL+"/error")
		assert.Error(err, "FetchMetadata should fail")
	})

	t.Run("bad metadata server response", func(t *testing.T) {
		_, err := FetchMetadata(context.Background(), ts.URL+"/bad-metadata")
		assert.Error(err, "FetchMetadata should fail")
	})

	for _, wk := range WellKnown {
		t.Run(wk, func(t *testing.T) {
			m, err := FetchMetadata(context.Background(), ts.URL+"/.well-known/"+wk)
			if !assert.NoError(err, "FetchMetadata should succeed") {
				return
			}
			assert.Equal(m.Issuer, ts.URL+"/")
			assert.Equal(m.AuthURL, ts.URL+"/authorize")
			assert.Equal(m.TokenURL, ts.URL+"/token")
			assert.Equal(m.JWKSURL, ts.URL+"/jwk")
			assert.Equal(m.RegistrationURL, ts.URL+"/register")
			assert.Equal(m.UserInfoURL, ts.URL+"/userinfo")
			assert.Equal(m.Scopes, []string{
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
				"eduperson_entitlement",
			})
			assert.Equal(m.ResponseTypes, []string{"code", "token"})
		})
	}
}

func TestIssuerKeyURL(t *testing.T) {
	assert := assert.New(t)
	srv, err := newFakeAuthServer()
	if !assert.NoError(err) {
		return
	}
	ts := httptest.NewTLSServer(srv)
	defer ts.Close()
	http.DefaultClient = ts.Client()

	t.Run("nil context", func(t *testing.T) {
		_, err := IssuerKeyURL(nil, "https://example.com")
		assert.Error(err, "IssuerKeyURL should fail")
	})

	t.Run("no supported well-known suffix", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "not found", http.StatusNotFound)
		}))
		defer ts.Close()
		http.DefaultClient = ts.Client()
		_, err := IssuerKeyURL(context.Background(), ts.URL)
		if !assert.Error(err, "IssuerKeyURL should fail") {
			return
		}
	})

	for _, wk := range WellKnown {
		t.Run(wk, func(t *testing.T) {
			// need a test server that _only_ responds to the specific well-known suffix
			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case path.Join("/.well-known", wk):
					fmt.Fprintln(w, "{\"jwks_uri\": \"https://example.com/jwk\"}")
				default:
					http.Error(w, "bad path", http.StatusNotFound)
				}
			}))
			defer ts.Close()
			http.DefaultClient = ts.Client()
			u, err := IssuerKeyURL(context.Background(), ts.URL)
			if !assert.NoError(err, "IssuerKeyURL should succeed") {
				return
			}
			assert.Equal(u, "https://example.com/jwk")
		})
	}
}

func TestGetIssuerKeys(t *testing.T) {
	assert := assert.New(t)
	srv, err := newFakeAuthServer()
	if !assert.NoError(err) {
		return
	}
	ts := httptest.NewTLSServer(srv)
	defer ts.Close()
	http.DefaultClient = ts.Client()

	t.Run("nil context", func(t *testing.T) {
		_, err := GetIssuerKeys(nil, "https://example.com")
		assert.Error(err, "GetIssuerKeys should fail")
	})

	_, err = GetIssuerKeys(context.Background(), ts.URL)
	if !assert.NoError(err, "GetIssuerKeys should succeed") {
		return
	}
}

func TestIssuerKeyManager(t *testing.T) {
	assert := assert.New(t)
	srv, err := newFakeAuthServer()
	if !assert.NoError(err) {
		return
	}
	ts := httptest.NewTLSServer(srv)
	defer ts.Close()
	http.DefaultClient = ts.Client()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	t.Run("IssuerKeyManager not initialized", func(t *testing.T) {
		ikm := IssuerKeyManager{}
		err := ikm.AddIssuer(ctx, "https://example.com")
		assert.Error(err)
		assert.ErrorIs(err, IKMNotInitializedError)

		_, err = ikm.GetIssuerKeys(ctx, "https://example.com")
		assert.Error(err)
		assert.ErrorIs(err, IKMNotInitializedError)

		_, err = ikm.KeySetFrom(jwt.New())
		assert.Error(err)
		assert.ErrorIs(err, IKMNotInitializedError)
	})

	ikm := NewIssuerKeyManager(ctx)
	assert.Equal(ikm.issuerKeyURLs, map[string]string{})
	assert.IsType(jwk.NewAutoRefresh(ctx), ikm.keysets)

	assert.Error(ikm.AddIssuer(ctx, "foo://bar/baz"), "adding bad issuer should fail")
	assert.Equal(ikm.issuerKeyURLs, map[string]string{}, "bad issuer shouldn't have been added")

	t.Run("add issuer", func(t *testing.T) {
		if !assert.NoError(ikm.AddIssuer(ctx, ts.URL)) {
			return
		}
		u, ok := ikm.issuerKeyURLs[ts.URL]
		assert.True(ok, "issuer should have been added")
		if !assert.Equal(u, ts.URL+"/jwk", "JWK URL should be set") {
			return
		}
	})

	t.Run("get issuer keys", func(t *testing.T) {
		_, err := ikm.GetIssuerKeys(ctx, "https://example.com")
		assert.Error(err, "GetIssuerKeys should fail for issuer that has not been added")
		assert.ErrorIs(err, UntrustedIssuerError)

		ks, err := ikm.GetIssuerKeys(ctx, ts.URL)
		if !assert.NoError(err, "GetIssuerKeys should succeed") {
			return
		}
		assert.Equal(ks.Len(), 1, "keyset should have one key")
	})

	t.Run("get key set for token issuer", func(t *testing.T) {
		t1 := jwt.New()
		t1.Set("iss", "https://example.com")
		_, err := ikm.KeySetFrom(t1)
		assert.Error(err, "KeySetFrom should fail for token with issuer that has not been added")
		assert.ErrorIs(err, UntrustedIssuerError)

		t1.Set("iss", ts.URL)
		ks, err := ikm.KeySetFrom(t1)
		if !assert.NoError(err, "KeySetFrom should succeed") {
			return
		}
		assert.Equal(ks.Len(), 1, "keyset should have one key")
	})
}

func TestIssuerKeyFetcher(t *testing.T) {
	assert := assert.New(t)
	srv, err := newFakeAuthServer()
	if !assert.NoError(err) {
		return
	}
	ts := httptest.NewTLSServer(srv)
	defer ts.Close()
	http.DefaultClient = ts.Client()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	t.Run("IssuerKeyFetcher not initialized", func(t *testing.T) {
		ikf := IssuerKeyFetcher{}
		_, err = ikf.GetIssuerKeys(ctx, ts.URL)
		assert.ErrorIs(err, UntrustedIssuerError, "unitialized IssuerKeyFetcher can be used, but doesn't trust any issuers")
		_, err = ikf.KeySetFrom(jwt.New())
		assert.ErrorIs(err, UntrustedIssuerError, "unitialized IssuerKeyFetcher can be used, but doesn't trust any issuers")

		err := ikf.AddIssuer(ctx, ts.URL)
		assert.NoError(err, "IssuerKeyFetcher doesn't need to be initialized")

		_, err = ikf.GetIssuerKeys(ctx, ts.URL)
		assert.NoError(err)
	})

	ikf := NewIssuerKeyFetcher("https://example.com")
	assert.Equal(map[string]bool{"https://example.com": true}, ikf.issuers)

	t.Run("add issuer", func(t *testing.T) {
		if !assert.NoError(ikf.AddIssuer(ctx, ts.URL)) {
			return
		}
		_, ok := ikf.issuers[ts.URL]
		assert.True(ok, "issuer should have been added")
	})

	t.Run("get issuer keys", func(t *testing.T) {
		_, err := ikf.GetIssuerKeys(ctx, "https://bad.example.com")
		assert.Error(err, "GetIssuerKeys should fail for issuer that has not been added")
		assert.ErrorIs(err, UntrustedIssuerError)

		ks, err := ikf.GetIssuerKeys(ctx, ts.URL)
		if !assert.NoError(err, "GetIssuerKeys should succeed") {
			return
		}
		assert.Equal(ks.Len(), 1, "keyset should have one key")
	})

	t.Run("get key set for token issuer", func(t *testing.T) {
		t1 := jwt.New()
		t1.Set("iss", "https://bad.example.com")
		_, err := ikf.KeySetFrom(t1)
		assert.Error(err, "KeySetFrom should fail for token with issuer that has not been added")
		assert.ErrorIs(err, UntrustedIssuerError)

		t1.Set("iss", ts.URL)
		ks, err := ikf.KeySetFrom(t1)
		if !assert.NoError(err, "KeySetFrom should succeed") {
			return
		}
		assert.Equal(ks.Len(), 1, "keyset should have one key")
	})
}

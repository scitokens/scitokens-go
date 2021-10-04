package scitokens

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path"
	"testing"
	"text/template"

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
	testMetadata = template.Must(template.New("metadata").Parse(testMetadataTemplate))
	testJWKs     = `{
  "keys": [
    {
      "kty": "RSA",
      "e": "AQAB",
      "kid": "rsa1",
      "n": "gTuRCL3TJU40hx43uXqKUWSIanP6D63A8u0V4GTsdvdamGOUyq084_aeC38pK8eI-D4JaUyTKoyiR2vFRPd3UnqhNVx-smHwywYu2q4lWpAKia2iTnXJeEh9cAcdjWxzgj41MNiWtpoJmJLoNWMx3OGvyNT9z4hNxcSkREmh-LU"
    }
  ]
}`
)

func fakeAuthServerHandler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.well-known/oauth-authorization-server",
		"/.well-known/openid-configuration":
		if err := testMetadata.Execute(w, r); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	case "/bad-metadata":
		fmt.Fprintln(w, "{foo:bar}")
	case "/jwk":
		fmt.Fprintln(w, testJWKs)
	case "/private":
		http.Error(w, "forbidden", http.StatusForbidden)
	case "/error":
		http.Error(w, "error", http.StatusInternalServerError)
	default:
		http.Error(w, "bad path", http.StatusNotFound)
	}
}

func TestFetchMetadata(t *testing.T) {
	assert := assert.New(t)
	ts := httptest.NewTLSServer(http.HandlerFunc(fakeAuthServerHandler))
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
		assert.ErrorIs(err, NotFoundError{})
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
	ts := httptest.NewTLSServer(http.HandlerFunc(fakeAuthServerHandler))
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
					if err := testMetadata.Execute(w, r); err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
					}
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
			assert.Equal(u, ts.URL+"/jwk")
		})
	}
}

func TestGetIssuerKeys(t *testing.T) {
	assert := assert.New(t)
	ts := httptest.NewTLSServer(http.HandlerFunc(fakeAuthServerHandler))
	defer ts.Close()
	http.DefaultClient = ts.Client()

	t.Run("nil context", func(t *testing.T) {
		_, err := GetIssuerKeys(nil, "https://example.com")
		assert.Error(err, "GetIssuerKeys should fail")
	})

	_, err := GetIssuerKeys(context.Background(), ts.URL)
	if !assert.NoError(err, "GetIssuerKeys should succeed") {
		return
	}
}

func TestIssuerKeyManager(t *testing.T) {
	assert := assert.New(t)
	ts := httptest.NewTLSServer(http.HandlerFunc(fakeAuthServerHandler))
	defer ts.Close()
	http.DefaultClient = ts.Client()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	t.Run("IssuerKeyManager not initialized", func(t *testing.T) {
		ikm := IssuerKeyManager{}
		assert.Error(ikm.AddIssuer(ctx, "https://example.com"))
		_, err := ikm.GetIssuerKeys(ctx, "https://example.com")
		assert.Error(err)
		_, err = ikm.KeySetFrom(jwt.New())
		assert.Error(err)
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

		t1.Set("iss", ts.URL)
		ks, err := ikm.KeySetFrom(t1)
		if !assert.NoError(err, "KeySetFrom should succeed") {
			return
		}
		assert.Equal(ks.Len(), 1, "keyset should have one key")
	})
}

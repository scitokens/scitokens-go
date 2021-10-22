package issuer

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path"
	"testing"

	"github.com/scitokens/scitokens-go/internal"
	"github.com/stretchr/testify/assert"
)

func TestFetchMetadata(t *testing.T) {
	assert := assert.New(t)
	srv, err := internal.NewFakeAuthServer()
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

func TestKeyURL(t *testing.T) {
	assert := assert.New(t)
	srv, err := internal.NewFakeAuthServer()
	if !assert.NoError(err) {
		return
	}
	ts := httptest.NewTLSServer(srv)
	defer ts.Close()
	http.DefaultClient = ts.Client()

	t.Run("nil context", func(t *testing.T) {
		_, err := KeyURL(nil, "https://example.com")
		assert.Error(err, "KeyURL should fail")
	})

	t.Run("no supported well-known suffix", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "not found", http.StatusNotFound)
		}))
		defer ts.Close()
		http.DefaultClient = ts.Client()
		_, err := KeyURL(context.Background(), ts.URL)
		if !assert.Error(err, "KeyURL should fail") {
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
			u, err := KeyURL(context.Background(), ts.URL)
			if !assert.NoError(err, "KeyURL should succeed") {
				return
			}
			assert.Equal(u, "https://example.com/jwk")
		})
	}
}

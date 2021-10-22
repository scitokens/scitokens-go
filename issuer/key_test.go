package issuer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/scitokens/scitokens-go/internal"
	"github.com/stretchr/testify/assert"
)

func TestGetKeys(t *testing.T) {
	assert := assert.New(t)
	srv, err := internal.NewFakeAuthServer()
	if !assert.NoError(err) {
		return
	}
	ts := httptest.NewTLSServer(srv)
	defer ts.Close()
	http.DefaultClient = ts.Client()

	t.Run("nil context", func(t *testing.T) {
		_, err := GetKeys(nil, "https://example.com")
		assert.Error(err, "GetKeys should fail")
	})

	_, err = GetKeys(context.Background(), ts.URL)
	if !assert.NoError(err, "GetKeys should succeed") {
		return
	}
}

func TestKeyManager(t *testing.T) {
	assert := assert.New(t)
	srv, err := internal.NewFakeAuthServer()
	if !assert.NoError(err) {
		return
	}
	ts := httptest.NewTLSServer(srv)
	defer ts.Close()
	http.DefaultClient = ts.Client()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	t.Run("KeyManager not initialized", func(t *testing.T) {
		ikm := KeyManager{}
		err := ikm.AddIssuer(ctx, "https://example.com")
		assert.Error(err)
		assert.ErrorIs(err, KeyManagerNotInitializedError)

		_, err = ikm.GetKeys(ctx, "https://example.com")
		assert.Error(err)
		assert.ErrorIs(err, KeyManagerNotInitializedError)

		_, err = ikm.KeySetFrom(jwt.New())
		assert.Error(err)
		assert.ErrorIs(err, KeyManagerNotInitializedError)
	})

	ikm := NewKeyManager(ctx)
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
		_, err := ikm.GetKeys(ctx, "https://example.com")
		assert.Error(err, "GetKeys should fail for issuer that has not been added")
		assert.ErrorIs(err, UntrustedIssuerError)

		ks, err := ikm.GetKeys(ctx, ts.URL)
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

func TestKeyFetcher(t *testing.T) {
	assert := assert.New(t)
	srv, err := internal.NewFakeAuthServer()
	if !assert.NoError(err) {
		return
	}
	ts := httptest.NewTLSServer(srv)
	defer ts.Close()
	http.DefaultClient = ts.Client()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	t.Run("KeyFetcher not initialized", func(t *testing.T) {
		ikf := KeyFetcher{}
		_, err = ikf.GetKeys(ctx, ts.URL)
		assert.ErrorIs(err, UntrustedIssuerError, "unitialized KeyFetcher can be used, but doesn't trust any issuers")
		_, err = ikf.KeySetFrom(jwt.New())
		assert.ErrorIs(err, UntrustedIssuerError, "unitialized KeyFetcher can be used, but doesn't trust any issuers")

		err := ikf.AddIssuer(ctx, ts.URL)
		assert.NoError(err, "KeyFetcher doesn't need to be initialized")

		_, err = ikf.GetKeys(ctx, ts.URL)
		assert.NoError(err)
	})

	ikf := NewKeyFetcher("https://example.com")
	assert.Equal(map[string]bool{"https://example.com": true}, ikf.issuers)

	t.Run("add issuer", func(t *testing.T) {
		if !assert.NoError(ikf.AddIssuer(ctx, ts.URL)) {
			return
		}
		_, ok := ikf.issuers[ts.URL]
		assert.True(ok, "issuer should have been added")
	})

	t.Run("get issuer keys", func(t *testing.T) {
		_, err := ikf.GetKeys(ctx, "https://bad.example.com")
		assert.Error(err, "GetKeys should fail for issuer that has not been added")
		assert.ErrorIs(err, UntrustedIssuerError)

		ks, err := ikf.GetKeys(ctx, ts.URL)
		if !assert.NoError(err, "GetKeys should succeed") {
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

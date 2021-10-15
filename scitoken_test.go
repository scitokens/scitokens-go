package scitokens

import (
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/jwt"
	"github.com/stretchr/testify/assert"
)

type testToken struct {
	Name     string
	Data     []byte
	Subject  string
	Issuer   string
	Scopes   []Scope
	Groups   []string
	Version  string
	Audience []string
}

var (
	// It goes without saying, but I'll say it anyways:
	// EXPIRED TOKENS ONLY
	testTokens = []testToken{
		{
			Name:    "bare SciToken",
			Data:    []byte("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJiYm9ja2VsbSIsImV4cCI6MTUwOTk5MTc5MCwiaXNzIjoiaHR0cHM6Ly9zY2l0b2tlbnMub3JnL2NtcyIsImlhdCI6MTUwOTk4ODE5MCwic2NvcGUiOiJyZWFkOi9zdG9yZSB3cml0ZTovc3RvcmUvdXNlci9iYm9ja2VsbSIsIm5iZiI6MTUwOTk4ODE5MCwidmVyIjoic2NpdG9rZW46Mi4wIiwiYXVkIjoiaHR0cHM6Ly9jbXMuZXhhbXBsZS5jb20ifQ.fCtyZQQNPaowQ5FXFVIlbt2Qpb4ui8Bkl1qXpwLKI3FQ0AKP64Ozf7NLKI8nRHaAqh9XRQAxB9YtAJAeHriSN422-CraARoYyBdrZMtwlxphOLPkpuxbIusVYB3r4zIRt4BoB7NlqLqwVV2e5rGtkJGvi9tpY2FNr7eZ6eBrzAg"),
			Subject: "bbockelm",
			Issuer:  "https://scitokens.org/cms",
			Scopes: []Scope{
				{"read", "/store"},
				{"write", "/store/user/bbockelm"},
			},
			Groups:   []string{},
			Version:  "scitoken:2.0",
			Audience: []string{"https://transfer-server.example.com"},
		},
		{
			Name:    "WLCG test issuer",
			Data:    []byte(`eyJraWQiOiJyc2ExIiwiYWxnIjoiUlMyNTYifQ.eyJ3bGNnLnZlciI6IjEuMCIsInN1YiI6ImM3NWMzMmNiLTU0ZGUtNDY2MC04NjVjLTFkNWM4NjlkMGQ3YSIsImF1ZCI6Imh0dHBzOlwvXC93bGNnLmNlcm4uY2hcL2p3dFwvdjFcL2FueSIsIm5iZiI6MTYzMzEyMTE1OCwic2NvcGUiOiJvcGVuaWQgcHJvZmlsZSBvZmZsaW5lX2FjY2VzcyBlbWFpbCB3bGNnIHdsY2cuZ3JvdXBzIiwiaXNzIjoiaHR0cHM6XC9cL3dsY2cuY2xvdWQuY25hZi5pbmZuLml0XC8iLCJleHAiOjE2MzMxMjQ3NTgsImlhdCI6MTYzMzEyMTE1OCwianRpIjoiOWU4OGFmNzAtZGIxMi00NWRlLWEwZTMtZDc3YTA0OTNhNzM0IiwiY2xpZW50X2lkIjoiY2Q1NjIzZTMtMTZkYS00MTU2LWEzNWYtYzBiOWU0MTkwZTA0Iiwid2xjZy5ncm91cHMiOlsiXC93bGNnIl19.dlz0VLighqFIyQ6wRk8kehRACfVnqSxRfZrAAaqneFgNCfhbGY65ZaAgCPHl2avfqRumYOqHr9PTbQLFp9bx6CV_Oa7kWguGOo2Dm59aoGO_XrlvhtGYJ3uxYUN6jQ8ZyQYaR8fgJmC3m1S_sVu56yg0HMC1jfFhCWec-cyes80`),
			Subject: "c75c32cb-54de-4660-865c-1d5c869d0d7a",
			Issuer:  "https://wlcg.cloud.cnaf.infn.it/",
			Scopes: []Scope{
				{"openid", ""},
				{"profile", ""},
				{"offline_access", ""},
				{"email", ""},
				{"wlcg", ""},
				{"wlcg.groups", ""},
			},
			Groups:   []string{"/wlcg"},
			Version:  "wlcg:1.0",
			Audience: []string{"https://wlcg.cern.ch/jwt/v1/any"},
		},
	}
)

func TestNewSciToken(t *testing.T) {
	t.Run("Bare non-SciToken", func(t *testing.T) {
		assert := assert.New(t)
		t1 := jwt.New()
		st, err := NewSciToken(t1)
		if !assert.NoError(err, "NewSciToken should succeed") {
			return
		}
		if !assert.NotNil(st, "SciToken should not be nil") {
			return
		}
		assert.Equal(st.Scopes(), []Scope{})
		assert.Equal(st.Groups(), []string{})
		assert.Equal(st.Audience(), t1.Audience())
		assert.Equal(st.Expiration(), t1.Expiration())
		assert.Equal(st.IssuedAt(), t1.IssuedAt())
		assert.Equal(st.Issuer(), t1.Issuer())
		assert.Equal(st.JwtID(), t1.JwtID())
		assert.Equal(st.NotBefore(), t1.NotBefore())
		assert.Equal(st.Subject(), t1.Subject())
		assert.Equal(st.PrivateClaims(), t1.PrivateClaims())
		assert.NoError(st.Set("foo", "bar"))
		foo, ok := st.Get("foo")
		assert.Equal(foo, "bar")
		assert.True(ok, "claim foo should be set")
		assert.NoError(st.Remove("foo"))
		_, ok = st.Get("foo")
		assert.False(ok, "claim foo should not be set after Remove()")
		st2, err := st.Clone()
		if !assert.NoError(err, "Clone() should succeed") {
			return
		}
		assert.Equal(st, st2)
	})
	t.Run("SciToken with scope and groups", func(t *testing.T) {
		assert := assert.New(t)
		t1 := jwt.New()
		if !assert.NoError(t1.Set("scope", "storage.read:/foo compute.run"), "setting scope should succeed") {
			return
		}
		if !assert.NoError(t1.Set("wlcg.groups", []interface{}{"/foo/bar", "/foo/baz"}), "setting groups should succeed") {
			return
		}
		st, err := NewSciToken(t1)
		if !assert.NoError(err, "NewSciToken should succeed") {
			return
		}
		if !assert.NotNil(st, "SciToken should not be nil") {
			return
		}
		assert.Equal(st.Scopes(), []Scope{
			{"storage.read", "/foo"},
			{"compute.run", ""},
		})
		assert.Equal(st.Groups(), []string{"/foo/bar", "/foo/baz"})
	})
	t.Run("SciToken with invalid scope", func(t *testing.T) {
		assert := assert.New(t)
		t1 := jwt.New()
		if !assert.NoError(t1.Set("scope", []interface{}{"foo", "bar"}), "setting scope should succeed") {
			return
		}
		_, err := NewSciToken(t1)
		assert.Error(err, "NewSciToken should fail")
	})
	t.Run("SciToken with invalid groups", func(t *testing.T) {
		assert := assert.New(t)
		t1 := jwt.New()
		if !assert.NoError(t1.Set("wlcg.groups", "foo,bar"), "setting groups should succeed") {
			return
		}
		_, err := NewSciToken(t1)
		assert.Error(err, "NewSciToken should fail")
	})
	t.Run("Parsed SciTokens", func(t *testing.T) {
		assert := assert.New(t)
		for _, tok := range testTokens {
			t.Run(tok.Name, func(t *testing.T) {
				t.Parallel()
				t1, err := jwt.Parse(tok.Data)
				if !assert.NoError(err, "jwt.Parse should succeed") {
					return
				}
				if !assert.Error(jwt.Validate(t1), "jwt.Validate should fail since token is expired") {
					return
				}
				// extend token expiration
				t1.Set("exp", time.Now().Add(60*time.Second))
				if !assert.NoError(jwt.Validate(t1), "jwt.Validate should pass with token extended") {
					return
				}
				st, err := NewSciToken(t1)
				if !assert.NoError(err, "NewSciToken should succeed") {
					return
				}
				if !assert.NotNil(st, "SciToken should not be nil") {
					return
				}
				assert.Equal(st.Subject(), tok.Subject)
				assert.Equal(st.Issuer(), tok.Issuer)
				assert.Equal(st.Scopes(), tok.Scopes)
				assert.Equal(st.Groups(), tok.Groups)
				assert.Equal(st.Version(), tok.Version)
				assert.Equal(st.Audience(), tok.Audience)
			})
		}
	})
}

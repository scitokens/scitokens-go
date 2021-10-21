package scitokens

import (
	"context"
	"time"

	"github.com/lestrrat-go/jwx/jwt"
)

// SciToken wraps a standard JWT token to add custom claims. Use NewSciToken()
// to wrap a jwt.Token and parse the custom claims.
type SciToken interface {
	jwt.Token
	Scopes() []Scope
	Groups() []string
	Version() string
}

type sciToken struct {
	token   jwt.Token
	scopes  []Scope
	groups  []string
	version string
}

// NewSciToken wraps a jwt.Token, populating the SciToken from the custom
// claims.
func NewSciToken(t jwt.Token) (SciToken, error) {
	st := &sciToken{
		token: t,
	}
	return st, st.update()
}

func (t *sciToken) update() error {
	var err error
	t.scopes, err = GetScopes(t)
	if err != nil {
		return err
	}

	t.groups, err = GetGroups(t)
	if err != nil {
		return err
	}

	t.version, err = GetVersion(t)
	if err != nil {
		return err
	}

	return nil
}

func (t *sciToken) Audience() []string {
	return t.token.Audience()
}

func (t *sciToken) Expiration() time.Time {
	return t.token.Expiration()
}

func (t *sciToken) IssuedAt() time.Time {
	return t.token.IssuedAt()
}

func (t *sciToken) Issuer() string {
	return t.token.Issuer()
}

func (t *sciToken) JwtID() string {
	return t.token.JwtID()
}

func (t *sciToken) NotBefore() time.Time {
	return t.token.NotBefore()
}

func (t *sciToken) Subject() string {
	return t.token.Subject()
}

func (t *sciToken) PrivateClaims() map[string]interface{} {
	return t.token.PrivateClaims()
}

func (t *sciToken) Get(name string) (interface{}, bool) {
	return t.token.Get(name)
}

func (t *sciToken) Set(name string, value interface{}) error {
	err := t.token.Set(name, value)
	if err != nil {
		return err
	}
	return t.update()
}

func (t *sciToken) Remove(name string) error {
	err := t.token.Remove(name)
	if err != nil {
		return err
	}
	return t.update()
}

func (t *sciToken) Clone() (jwt.Token, error) {
	nt, err := t.token.Clone()
	if err != nil {
		return nt, err
	}
	return NewSciToken(nt)
}

func (t *sciToken) Iterate(ctx context.Context) jwt.Iterator {
	return t.token.Iterate(ctx)
}

func (t *sciToken) Walk(ctx context.Context, v jwt.Visitor) error {
	return t.token.Walk(ctx, v)
}

func (t *sciToken) AsMap(ctx context.Context) (map[string]interface{}, error) {
	return t.token.AsMap(ctx)
}

func (t *sciToken) Scopes() []Scope {
	return t.scopes
}

func (t *sciToken) Groups() []string {
	return t.groups
}

func (t *sciToken) Version() string {
	return t.version
}

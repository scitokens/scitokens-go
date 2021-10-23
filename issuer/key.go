package issuer

import (
	"context"
	"errors"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

var (
	UntrustedIssuerError          = errors.New("issuer not trusted")
	KeyManagerNotInitializedError = errors.New("KeyManager not initialized")
)

// GetKeys returns all JSON Web Keys for the given issuer, fetching from
// the jwks_uri specified in the issuer's OAuth metadata. This will fetch the
// metadata and keys with every call, use an KeyManager to cache them for
// long-running processes.
func GetKeys(ctx context.Context, issuer string) (jwk.Set, error) {
	url, err := KeyURL(ctx, issuer)
	if err != nil {
		return nil, err
	}
	return jwk.Fetch(ctx, url)
}

// KeyProvider implements jwt.KeySetProvider, providing jwt.Parse... with
// the appropriate keys for one or more token issuers.
type KeyProvider interface {
	jwt.KeySetProvider
	AddIssuer(context.Context, string) error
	GetKeys(context.Context, string) (jwk.Set, error)
}

// KeyFetcher is a KeyProvider that fetches keys on demand.
type KeyFetcher struct {
	issuers map[string]bool
}

// NewKeyFetcher initializes a new key manager that DOES NOT cache keys,
// rather fetching them on demand. Use NewKeyManager() for long-lived
// processes.
func NewKeyFetcher(issuers ...string) *KeyFetcher {
	ikf := &KeyFetcher{}
	for _, iss := range issuers {
		ikf.AddIssuer(context.Background(), iss)
	}
	return ikf
}

// AddIssuer determines the JSON Web Keys URL for the given issuer, and adds it
// to the list of issuers trusted by this IssueKeyFetcher and accepted when
// using KeySetFrom() for validating tokens.
func (m *KeyFetcher) AddIssuer(ctx context.Context, issuer string) error {
	if m.issuers == nil {
		m.issuers = make(map[string]bool)
	}
	m.issuers[issuer] = true
	return nil
}

// GetKeys returns all JSON Web Keys for the given issuer, fetching from
// the jwks_uri specified in the issuer's OAuth metadata. AddIssuer() must be
// called first for this issuer or UntrsutedIssuerError will be returned.
func (m *KeyFetcher) GetKeys(ctx context.Context, issuer string) (jwk.Set, error) {
	if m.issuers == nil {
		return nil, UntrustedIssuerError
	}
	_, ok := m.issuers[issuer]
	if !ok {
		return nil, UntrustedIssuerError
	}
	return GetKeys(ctx, issuer)
}

// KeySetFrom returns the key set for the token, based on the token's issuer.
// The issuer must first be added to the KeyFetcher with AddIssuer() or
// UntrustedIssuerError will be returned.
func (m *KeyFetcher) KeySetFrom(t jwt.Token) (jwk.Set, error) {
	return m.GetKeys(context.Background(), t.Issuer())
}

// KeyManager is a KeyProvider that refreshes keys on a regular interval.
type KeyManager struct {
	// issuerKeyURLs is a cache of the JWKSURL for each issuer
	issuerKeyURLs map[string]string
	keysets       *jwk.AutoRefresh
}

// NewKeyManager initializes a new key manager. The Context controls the
// lifespan of the manager and its underlying objects.
func NewKeyManager(ctx context.Context) *KeyManager {
	return &KeyManager{
		issuerKeyURLs: make(map[string]string),
		keysets:       jwk.NewAutoRefresh(ctx),
	}
}

// AddIssuer determines the JSON Web Keys URL for the given issuer, and adds it
// to the list of issuers managed by this IssueKeyManager and accepted when
// using KeySetFrom() for validating tokens. Keys will be cached and refreshed
// at regular intervals, and can be accessed with GetKeys().
func (m *KeyManager) AddIssuer(ctx context.Context, issuer string) error {
	if m.keysets == nil {
		return KeyManagerNotInitializedError
	}
	if _, ok := m.issuerKeyURLs[issuer]; !ok {
		url, err := KeyURL(ctx, issuer)
		if err != nil {
			return err
		}
		m.keysets.Configure(url)
		m.issuerKeyURLs[issuer] = url
	}
	return nil
}

// GetKeys returns all JSON Web Keys for the given issuer, fetching from
// the jwks_uri specified in the issuer's OAuth metadata if necessary. The
// KeyManager will cache these keys, refreshing them at regular intervals.
// AddIssuer() must be called first for this issuer.
func (m *KeyManager) GetKeys(ctx context.Context, issuer string) (jwk.Set, error) {
	if m.keysets == nil {
		return nil, KeyManagerNotInitializedError
	}
	url, ok := m.issuerKeyURLs[issuer]
	if !ok {
		return nil, UntrustedIssuerError
	}
	return m.keysets.Fetch(ctx, url)
}

// KeySetFrom returns the key set for the token, based on the token's issuer.
// The issuer must first be added to the KeyManager with AddIssuer().
func (m *KeyManager) KeySetFrom(t jwt.Token) (jwk.Set, error) {
	if m.keysets == nil {
		return nil, KeyManagerNotInitializedError
	}
	return m.GetKeys(context.Background(), t.Issuer())
}

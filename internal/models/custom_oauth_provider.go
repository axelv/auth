package models

import (
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"strings"
	"time"

	"github.com/gobuffalo/pop/v6/slices"
	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/crypto"
	"github.com/supabase/auth/internal/storage"
)

// ProviderType represents the type of OAuth provider
type ProviderType string

const (
	ProviderTypeOAuth2 ProviderType = "oauth2"
	ProviderTypeOIDC   ProviderType = "oidc"
)

// Token endpoint client authentication methods (OIDC Core §9). A nil
// TokenEndpointAuthMethod auto-detects between the two client_secret methods.
const (
	TokenEndpointAuthClientSecretBasic = "client_secret_basic"
	TokenEndpointAuthClientSecretPost  = "client_secret_post"
	TokenEndpointAuthPrivateKeyJWT     = "private_key_jwt"
)

// CustomOAuthProvider represents a custom OAuth2 or OIDC provider configuration
type CustomOAuthProvider struct {
	ID           uuid.UUID    `db:"id" json:"id"`
	ProviderType ProviderType `db:"provider_type" json:"provider_type"`

	// Common fields for both OAuth2 and OIDC
	Identifier          string        `db:"identifier" json:"identifier"`
	Name                string        `db:"name" json:"name"`
	ClientID            string        `db:"client_id" json:"client_id"`
	ClientSecret        string        `db:"client_secret" json:"-"` // Encrypted via EncryptedString, never expose in JSON
	AcceptableClientIDs slices.String `db:"acceptable_client_ids" json:"acceptable_client_ids"`
	Scopes              slices.String `db:"scopes" json:"scopes"`
	PKCEEnabled         bool          `db:"pkce_enabled" json:"pkce_enabled"`
	AttributeMapping    slices.Map    `db:"attribute_mapping" json:"attribute_mapping"`
	// CustomClaimsAllowlist is a flat list of raw IdP claim keys copied verbatim
	// into custom_claims. Empty means no custom claims are captured.
	CustomClaimsAllowlist slices.String `db:"custom_claims_allowlist" json:"custom_claims_allowlist"`
	AuthorizationParams   slices.Map    `db:"authorization_params" json:"authorization_params"`
	Enabled               bool          `db:"enabled" json:"enabled"`
	EmailOptional         bool          `db:"email_optional" json:"email_optional"`

	// Token endpoint client authentication. ClientSigningKey is a PEM private
	// key used for private_key_jwt, encrypted like ClientSecret.
	TokenEndpointAuthMethod *string `db:"token_endpoint_auth_method" json:"token_endpoint_auth_method,omitempty"`
	ClientSigningKey        *string `db:"client_signing_key" json:"-"`
	ClientSigningKeyID      *string `db:"client_signing_key_id" json:"client_signing_key_id,omitempty"`

	// OIDC-specific fields (null for OAuth2 providers)
	Issuer            *string        `db:"issuer" json:"issuer,omitempty"`
	DiscoveryURL      *string        `db:"discovery_url" json:"discovery_url,omitempty"`
	SkipNonceCheck    bool           `db:"skip_nonce_check" json:"skip_nonce_check"`
	CachedDiscovery   *OIDCDiscovery `db:"cached_discovery" json:"discovery_document,omitempty"`
	DiscoveryCachedAt *time.Time     `db:"discovery_cached_at" json:"-"` // Internal caching, not exposed in API

	// OAuth2-specific fields (null for OIDC providers)
	AuthorizationURL *string `db:"authorization_url" json:"authorization_url,omitempty"`
	TokenURL         *string `db:"token_url" json:"token_url,omitempty"`
	UserinfoURL      *string `db:"userinfo_url" json:"userinfo_url,omitempty"`
	JwksURI          *string `db:"jwks_uri" json:"jwks_uri,omitempty"`

	// Timestamps
	CreatedAt time.Time `db:"created_at" json:"created_at"`
	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`
}

func (p CustomOAuthProvider) TableName() string {
	return "custom_oauth_providers"
}

// SetClientSecret encrypts and stores the client secret using the configured
// database encryption settings. If encryption is disabled, the secret is
// stored in plaintext (temporary fallback for now)
func (p *CustomOAuthProvider) SetClientSecret(secret string, dbEncryption conf.DatabaseEncryptionConfiguration) error {
	stored, err := p.encryptValue(secret, dbEncryption)
	if err != nil {
		return errors.Wrap(err, "error encrypting custom OAuth client secret")
	}
	p.ClientSecret = stored
	return nil
}

// SetClientSigningKey encrypts and stores the PEM private key used for
// private_key_jwt client authentication.
func (p *CustomOAuthProvider) SetClientSigningKey(pemKey string, dbEncryption conf.DatabaseEncryptionConfiguration) error {
	stored, err := p.encryptValue(pemKey, dbEncryption)
	if err != nil {
		return errors.Wrap(err, "error encrypting custom OAuth client signing key")
	}
	p.ClientSigningKey = &stored
	return nil
}

// GetClientSigningKey decrypts and returns the PEM private key, or "" if none is set.
func (p *CustomOAuthProvider) GetClientSigningKey(dbEncryption conf.DatabaseEncryptionConfiguration) (string, error) {
	if p.ClientSigningKey == nil {
		return "", nil
	}
	value, err := p.decryptValue(*p.ClientSigningKey, dbEncryption)
	if err != nil {
		return "", errors.Wrap(err, "error decrypting custom OAuth client signing key")
	}
	return value, nil
}

// UsesPrivateKeyJWT reports whether the token endpoint expects a signed client assertion.
func (p *CustomOAuthProvider) UsesPrivateKeyJWT() bool {
	return p.TokenEndpointAuthMethod != nil && *p.TokenEndpointAuthMethod == TokenEndpointAuthPrivateKeyJWT
}

// encryptValue encrypts a secret bound to this provider's ID. Empty values and
// deployments without database encryption store the value as-is.
func (p *CustomOAuthProvider) encryptValue(value string, dbEncryption conf.DatabaseEncryptionConfiguration) (string, error) {
	if value == "" || !dbEncryption.Encrypt {
		return value, nil
	}
	es, err := crypto.NewEncryptedString(p.ID.String(), []byte(value), dbEncryption.EncryptionKeyID, dbEncryption.EncryptionKey)
	if err != nil {
		return "", err
	}
	return es.String(), nil
}

// decryptValue reverses encryptValue, passing plaintext values through.
func (p *CustomOAuthProvider) decryptValue(stored string, dbEncryption conf.DatabaseEncryptionConfiguration) (string, error) {
	if stored == "" {
		return "", nil
	}
	es := crypto.ParseEncryptedString(stored)
	if es == nil {
		return stored, nil
	}
	if dbEncryption.DecryptionKeys == nil {
		return "", errors.New("database decryption keys not configured")
	}
	bytes, err := es.Decrypt(p.ID.String(), dbEncryption.DecryptionKeys)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// GetClientSecret decrypts and returns the client secret using the configured
// database decryption keys. It expects the client secret to be stored in
// encrypted form when encryption is enabled, but will also handle plaintext
// secrets (for deployments where encryption is not yet configured).
func (p *CustomOAuthProvider) GetClientSecret(dbEncryption conf.DatabaseEncryptionConfiguration) (string, error) {
	value, err := p.decryptValue(p.ClientSecret, dbEncryption)
	if err != nil {
		return "", errors.Wrap(err, "error decrypting custom OAuth client secret")
	}
	return value, nil
}

// IsOIDC returns true if this is an OIDC provider
func (p *CustomOAuthProvider) IsOIDC() bool {
	return p.ProviderType == ProviderTypeOIDC
}

// IsOAuth2 returns true if this is an OAuth2 provider
func (p *CustomOAuthProvider) IsOAuth2() bool {
	return p.ProviderType == ProviderTypeOAuth2
}

// GetProviderName returns the provider identifier (which already includes "custom:" prefix)
func (p *CustomOAuthProvider) GetProviderName() string {
	return p.Identifier
}

// GetDiscoveryURL returns the discovery URL for OIDC providers
// If discovery_url is set, use that; otherwise construct from issuer
func (p *CustomOAuthProvider) GetDiscoveryURL() string {
	if !p.IsOIDC() || p.Issuer == nil {
		return ""
	}

	if p.DiscoveryURL != nil && *p.DiscoveryURL != "" {
		return *p.DiscoveryURL
	}

	return strings.TrimRight(*p.Issuer, "/") + "/.well-known/openid-configuration"
}

// SetDiscoveryCache stores a validated OIDC discovery document and records the cache time.
func (p *CustomOAuthProvider) SetDiscoveryCache(discovery *OIDCDiscovery) {
	p.CachedDiscovery = discovery
	now := time.Now()
	p.DiscoveryCachedAt = &now
}

// ClearDiscoveryCache removes the cached discovery document.
func (p *CustomOAuthProvider) ClearDiscoveryCache() {
	p.CachedDiscovery = nil
	p.DiscoveryCachedAt = nil
}

// OIDCDiscovery represents cached OIDC discovery document
type OIDCDiscovery struct {
	Issuer                 string   `json:"issuer"`
	AuthorizationEndpoint  string   `json:"authorization_endpoint"`
	TokenEndpoint          string   `json:"token_endpoint"`
	UserinfoEndpoint       string   `json:"userinfo_endpoint,omitempty"`
	JwksURI                string   `json:"jwks_uri"`
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported []string `json:"response_types_supported,omitempty"`
	GrantTypesSupported    []string `json:"grant_types_supported,omitempty"`
	SubjectTypesSupported  []string `json:"subject_types_supported,omitempty"`
}

func (d *OIDCDiscovery) Scan(src interface{}) error {
	if src == nil {
		return nil
	}

	b, ok := src.([]byte)
	if !ok {
		str, ok := src.(string)
		if !ok {
			return errors.New("scan source was not []byte or string")
		}
		b = []byte(str)
	}

	if err := json.Unmarshal(b, d); err != nil {
		return errors.Wrap(err, "error unmarshaling OIDC discovery")
	}

	return nil
}

func (d *OIDCDiscovery) Value() (driver.Value, error) {
	if d == nil {
		return nil, nil
	}

	b, err := json.Marshal(d)
	if err != nil {
		return nil, errors.Wrap(err, "error marshaling OIDC discovery")
	}

	return b, nil
}

// CRUD operations for CustomOAuthProvider

// FindCustomOAuthProviderByID finds a custom OAuth provider by ID
func FindCustomOAuthProviderByID(tx *storage.Connection, id uuid.UUID) (*CustomOAuthProvider, error) {
	var provider CustomOAuthProvider

	if err := tx.Q().Where("id = ?", id).First(&provider); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, CustomOAuthProviderNotFoundError{}
		}
		return nil, errors.Wrap(err, "error finding custom OAuth provider by ID")
	}

	return &provider, nil
}

// FindCustomOAuthProviderByIdentifier finds a custom OAuth provider by identifier
func FindCustomOAuthProviderByIdentifier(tx *storage.Connection, identifier string) (*CustomOAuthProvider, error) {
	var provider CustomOAuthProvider

	if err := tx.Q().Where("identifier = ?", identifier).First(&provider); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, CustomOAuthProviderNotFoundError{}
		}
		return nil, errors.Wrap(err, "error finding custom OAuth provider by identifier")
	}

	return &provider, nil
}

// FindAllCustomOAuthProviders finds all custom OAuth providers
func FindAllCustomOAuthProviders(tx *storage.Connection) ([]*CustomOAuthProvider, error) {
	var providers []*CustomOAuthProvider

	if err := tx.Q().Order("created_at desc").All(&providers); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return []*CustomOAuthProvider{}, nil
		}
		return nil, errors.Wrap(err, "error finding all custom OAuth providers")
	}

	return providers, nil
}

// FindAllCustomOAuthProvidersByType finds all custom OAuth providers of a specific type
func FindAllCustomOAuthProvidersByType(tx *storage.Connection, providerType ProviderType) ([]*CustomOAuthProvider, error) {
	var providers []*CustomOAuthProvider

	if err := tx.Q().Where("provider_type = ?", providerType).Order("provider_type desc").All(&providers); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return []*CustomOAuthProvider{}, nil
		}
		return nil, errors.Wrap(err, "error finding custom OAuth providers by type")
	}

	return providers, nil
}

// CountCustomOAuthProviders counts all custom OAuth providers
func CountCustomOAuthProviders(tx *storage.Connection) (int, error) {
	count, err := tx.Q().Count(&CustomOAuthProvider{})
	if err != nil {
		return 0, errors.Wrap(err, "error counting custom OAuth providers")
	}
	return count, nil
}

// CreateCustomOAuthProvider creates a new custom OAuth provider
func CreateCustomOAuthProvider(tx *storage.Connection, provider *CustomOAuthProvider) error {
	if provider.ID == uuid.Nil {
		id, err := uuid.NewV4()
		if err != nil {
			return errors.Wrap(err, "error generating custom OAuth provider ID")
		}
		provider.ID = id
	}

	// Ensure text[] fields are never nil (Postgres NOT NULL constraint)
	if provider.Scopes == nil {
		provider.Scopes = slices.String{}
	}
	if provider.AcceptableClientIDs == nil {
		provider.AcceptableClientIDs = slices.String{}
	}
	if provider.CustomClaimsAllowlist == nil {
		provider.CustomClaimsAllowlist = slices.String{}
	}

	if err := tx.Create(provider); err != nil {
		return errors.Wrap(err, "error creating custom OAuth provider")
	}

	return nil
}

// UpdateCustomOAuthProvider updates an existing custom OAuth provider
func UpdateCustomOAuthProvider(tx *storage.Connection, provider *CustomOAuthProvider) error {
	// Set updated_at timestamp explicitly in application code
	provider.UpdatedAt = time.Now()
	if err := tx.Update(provider); err != nil {
		return errors.Wrap(err, "error updating custom OAuth provider")
	}
	return nil
}

// DeleteCustomOAuthProvider deletes a custom OAuth provider
func DeleteCustomOAuthProvider(tx *storage.Connection, id uuid.UUID) error {
	if err := tx.Destroy(&CustomOAuthProvider{ID: id}); err != nil {
		return errors.Wrap(err, "error deleting custom OAuth provider")
	}
	return nil
}

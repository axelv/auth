package provider

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

const (
	clientAssertionType     = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	clientAssertionLifetime = 60 * time.Second
)

// ClientAuth selects how a custom provider authenticates at its token endpoint
// (OIDC Core §9). The zero value keeps x/oauth2's auto-detection between
// client_secret_basic and client_secret_post.
type ClientAuth struct {
	Method     string
	SigningKey crypto.Signer
	KeyID      string
}

// NewClientAuth builds a ClientAuth from stored provider settings. pemKey is
// only used, and then required, for private_key_jwt.
func NewClientAuth(method, pemKey, keyID string) (ClientAuth, error) {
	switch method {
	case "", "client_secret_basic", "client_secret_post":
		return ClientAuth{Method: method}, nil
	case "private_key_jwt":
		key, err := ParseClientSigningKey(pemKey)
		if err != nil {
			return ClientAuth{}, err
		}
		return ClientAuth{Method: method, SigningKey: key, KeyID: keyID}, nil
	default:
		return ClientAuth{}, fmt.Errorf("unsupported token endpoint auth method %q", method)
	}
}

// ParseClientSigningKey parses a PEM private key (PKCS#8, PKCS#1 or SEC 1) and
// checks that a JWS algorithm exists for it.
func ParseClientSigningKey(pemKey string) (crypto.Signer, error) {
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {
		return nil, errors.New("client signing key is not PEM encoded")
	}

	var parsed interface{}
	var err error
	switch block.Type {
	case "RSA PRIVATE KEY":
		parsed, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		parsed, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	}
	if err != nil {
		return nil, fmt.Errorf("invalid client signing key: %w", err)
	}

	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, errors.New("client signing key is not a signing key")
	}
	if _, err := signingMethodFor(signer); err != nil {
		return nil, err
	}
	return signer, nil
}

func signingMethodFor(key crypto.Signer) (jwt.SigningMethod, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		if k.N.BitLen() < 2048 {
			return nil, errors.New("RSA client signing key must be at least 2048 bits")
		}
		return jwt.SigningMethodRS256, nil
	case *ecdsa.PrivateKey:
		switch k.Curve {
		case elliptic.P256():
			return jwt.SigningMethodES256, nil
		case elliptic.P384():
			return jwt.SigningMethodES384, nil
		case elliptic.P521():
			return jwt.SigningMethodES512, nil
		}
		return nil, errors.New("unsupported EC curve for client signing key")
	case ed25519.PrivateKey:
		return jwt.SigningMethodEdDSA, nil
	}
	return nil, errors.New("unsupported client signing key type")
}

// apply sets the oauth2 auth style for the configured method. private_key_jwt
// sends client_id in the form and no secret; the assertion is added per exchange.
func (a ClientAuth) apply(config *oauth2.Config) {
	switch a.Method {
	case "client_secret_basic":
		config.Endpoint.AuthStyle = oauth2.AuthStyleInHeader
	case "client_secret_post":
		config.Endpoint.AuthStyle = oauth2.AuthStyleInParams
	case "private_key_jwt":
		config.Endpoint.AuthStyle = oauth2.AuthStyleInParams
		config.ClientSecret = ""
	}
}

// exchangeOptions returns the extra token request parameters for this method.
// Each call signs a fresh single-use assertion (RFC 7523 §3).
func (a ClientAuth) exchangeOptions(config *oauth2.Config) ([]oauth2.AuthCodeOption, error) {
	if a.Method != "private_key_jwt" {
		return nil, nil
	}

	method, err := signingMethodFor(a.SigningKey)
	if err != nil {
		return nil, err
	}
	jti, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	token := jwt.NewWithClaims(method, jwt.RegisteredClaims{
		Issuer:    config.ClientID,
		Subject:   config.ClientID,
		Audience:  jwt.ClaimStrings{config.Endpoint.TokenURL},
		ID:        jti.String(),
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(clientAssertionLifetime)),
	})
	if a.KeyID != "" {
		token.Header["kid"] = a.KeyID
	}

	assertion, err := token.SignedString(a.SigningKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign client assertion: %w", err)
	}

	return []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("client_assertion_type", clientAssertionType),
		oauth2.SetAuthURLParam("client_assertion", assertion),
	}, nil
}

// exchange runs the authorization code exchange with this client authentication.
func (a ClientAuth) exchange(ctx context.Context, config *oauth2.Config, code string, opts []oauth2.AuthCodeOption) (*oauth2.Token, error) {
	extra, err := a.exchangeOptions(config)
	if err != nil {
		return nil, err
	}
	return config.Exchange(ctx, code, append(opts, extra...)...)
}

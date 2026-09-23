package provider

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/supabase/auth/internal/conf"
	"golang.org/x/oauth2"
)

// Token endpoint auth methods (RFC 7591 registry). models holds the same
// values but imports this package, so they cannot be shared from there.
const (
	clientSecretBasic = "client_secret_basic"
	clientSecretPost  = "client_secret_post"
	privateKeyJWT     = "private_key_jwt"
)

const (
	clientAssertionType     = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	clientAssertionLifetime = 60 * time.Second
	minRSAKeyBits           = 2048
)

// ClientAuth selects how a custom provider authenticates at its token endpoint
// (OIDC Core §9). The zero value keeps x/oauth2's auto-detection between
// client_secret_basic and client_secret_post.
type ClientAuth struct {
	Method     string
	signingKey jwk.Key
}

// NewClientAuth builds a ClientAuth from stored provider settings. signingKey
// is only used, and then required, for private_key_jwt; keyID overrides the
// key's own kid when set.
func NewClientAuth(method, signingKey, keyID string) (ClientAuth, error) {
	switch method {
	case "", clientSecretBasic, clientSecretPost:
		return ClientAuth{Method: method}, nil
	case privateKeyJWT:
		key, err := ParseClientSigningKey(signingKey)
		if err != nil {
			return ClientAuth{}, err
		}
		if keyID != "" {
			if err := key.Set(jwk.KeyIDKey, keyID); err != nil {
				return ClientAuth{}, err
			}
		}
		return ClientAuth{Method: method, signingKey: key}, nil
	default:
		return ClientAuth{}, fmt.Errorf("unsupported token endpoint auth method %q", method)
	}
}

// ParseClientSigningKey parses an asymmetric private key given as a JWK or in
// PEM form. A key without "alg" gets the default algorithm for its type, and
// the key is test-signed so an unusable key is rejected up front.
func ParseClientSigningKey(value string) (jwk.Key, error) {
	value = strings.TrimSpace(value)
	var key jwk.Key
	var err error
	if strings.HasPrefix(value, "{") {
		key, err = jwk.ParseKey([]byte(value))
	} else {
		key, err = jwk.ParseKey([]byte(value), jwk.WithPEM(true))
	}
	if err != nil {
		return nil, fmt.Errorf("client signing key is not a valid JWK or PEM private key: %w", err)
	}

	alg, err := defaultSigningAlg(key)
	if err != nil {
		return nil, err
	}
	if key.Algorithm().String() == "" {
		if err := key.Set(jwk.AlgorithmKey, alg); err != nil {
			return nil, err
		}
	}

	// conf.GetSigningAlg falls back to HS256 for algorithms it does not know.
	if conf.GetSigningAlg(key) == jwt.SigningMethodHS256 {
		return nil, fmt.Errorf("unsupported client signing key algorithm %q", key.Algorithm())
	}
	if _, err := signClientAssertion(key, jwt.MapClaims{}); err != nil {
		return nil, fmt.Errorf("client signing key cannot sign: %w", err)
	}
	return key, nil
}

// defaultSigningAlg checks that key is a usable asymmetric private key and
// returns the JWS algorithm to use when the key does not name one.
func defaultSigningAlg(key jwk.Key) (jwa.SignatureAlgorithm, error) {
	switch k := key.(type) {
	case jwk.RSAPrivateKey:
		if len(k.N())*8 < minRSAKeyBits {
			return "", fmt.Errorf("RSA client signing key must be at least %d bits", minRSAKeyBits)
		}
		return jwa.RS256, nil
	case jwk.ECDSAPrivateKey:
		switch k.Crv() {
		case jwa.P256:
			return jwa.ES256, nil
		case jwa.P384:
			return jwa.ES384, nil
		case jwa.P521:
			return jwa.ES512, nil
		}
		return "", fmt.Errorf("unsupported EC curve %q for client signing key", k.Crv())
	case jwk.OKPPrivateKey:
		if k.Crv() == jwa.Ed25519 {
			return jwa.EdDSA, nil
		}
		return "", fmt.Errorf("unsupported OKP curve %q for client signing key", k.Crv())
	}
	return "", errors.New("client signing key must be an RSA, EC or Ed25519 private key")
}

// signClientAssertion signs claims with key, setting kid when the key has one.
func signClientAssertion(key jwk.Key, claims jwt.MapClaims) (string, error) {
	var raw any
	if err := key.Raw(&raw); err != nil {
		return "", err
	}
	token := jwt.NewWithClaims(conf.GetSigningAlg(key), claims)
	if kid := key.KeyID(); kid != "" {
		token.Header["kid"] = kid
	}
	return token.SignedString(raw)
}

// apply sets the oauth2 auth style for the configured method. private_key_jwt
// sends client_id in the form and no secret; the assertion is added per exchange.
func (a ClientAuth) apply(config *oauth2.Config) {
	switch a.Method {
	case clientSecretBasic:
		config.Endpoint.AuthStyle = oauth2.AuthStyleInHeader
	case clientSecretPost:
		config.Endpoint.AuthStyle = oauth2.AuthStyleInParams
	case privateKeyJWT:
		config.Endpoint.AuthStyle = oauth2.AuthStyleInParams
		config.ClientSecret = ""
	}
}

// exchangeOptions returns the extra token request parameters for this method.
// Each call signs a fresh single-use assertion (RFC 7523 §3).
func (a ClientAuth) exchangeOptions(config *oauth2.Config) ([]oauth2.AuthCodeOption, error) {
	if a.Method != privateKeyJWT {
		return nil, nil
	}

	jti, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	// aud is a plain string on purpose: jwt.ClaimStrings encoding depends on the
	// process-wide jwt.MarshalSingleStringAsArray, which tokens.SignJWT flips.
	assertion, err := signClientAssertion(a.signingKey, jwt.MapClaims{
		"iss": config.ClientID,
		"sub": config.ClientID,
		"aud": config.Endpoint.TokenURL,
		"jti": jti.String(),
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": now.Add(clientAssertionLifetime).Unix(),
	})
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

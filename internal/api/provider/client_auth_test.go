package provider

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type tokenRequest struct {
	form          url.Values
	authorization string
}

// newRecordingTokenServer returns a token endpoint that records each request.
func newRecordingTokenServer(t *testing.T) (*httptest.Server, *[]tokenRequest) {
	t.Helper()
	var requests []tokenRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		requests = append(requests, tokenRequest{form: r.PostForm, authorization: r.Header.Get("Authorization")})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "at", "token_type": "Bearer", "expires_in": 60})
	}))
	t.Cleanup(server.Close)
	return server, &requests
}

func newTestCustomOAuthProvider(tokenURL, clientSecret string) *CustomOAuthProvider {
	return NewCustomOAuthProvider(
		"client-123", clientSecret,
		"https://idp.example.com/authorize", tokenURL, "https://idp.example.com/userinfo",
		"https://auth.example.com/callback",
		[]string{"openid"}, false, nil, nil, nil, nil,
	)
}

func pemEncodePKCS8(t *testing.T, key interface{}) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func TestClientAuth_PrivateKeyJWT(t *testing.T) {
	server, requests := newRecordingTokenServer(t)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	auth, err := NewClientAuth("private_key_jwt", pemEncodePKCS8(t, rsaKey), "key-1")
	require.NoError(t, err)

	p := newTestCustomOAuthProvider(server.URL, "must-not-be-sent")
	p.SetClientAuth(auth)

	_, err = p.GetOAuthToken(context.Background(), "the-code")
	require.NoError(t, err)
	_, err = p.GetOAuthToken(context.Background(), "the-code")
	require.NoError(t, err)
	require.Len(t, *requests, 2)

	req := (*requests)[0]
	assert.Empty(t, req.authorization, "no client_secret_basic header")
	assert.Empty(t, req.form.Get("client_secret"))
	assert.Equal(t, "client-123", req.form.Get("client_id"))
	assert.Equal(t, clientAssertionType, req.form.Get("client_assertion_type"))

	var claims jwt.RegisteredClaims
	parsed, err := jwt.ParseWithClaims(req.form.Get("client_assertion"), &claims, func(token *jwt.Token) (interface{}, error) {
		return &rsaKey.PublicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithAudience(server.URL), jwt.WithIssuer("client-123"))
	require.NoError(t, err)
	assert.Equal(t, "key-1", parsed.Header["kid"])
	assert.Equal(t, "client-123", claims.Subject)
	assert.NotEmpty(t, claims.ID)
	assert.WithinDuration(t, time.Now().Add(clientAssertionLifetime), claims.ExpiresAt.Time, 5*time.Second)

	second := (*requests)[1].form.Get("client_assertion")
	assert.NotEqual(t, req.form.Get("client_assertion"), second, "each exchange signs a fresh assertion")
}

func TestClientAuth_ClientSecretMethods(t *testing.T) {
	t.Run("client_secret_post sends the secret in the form only", func(t *testing.T) {
		server, requests := newRecordingTokenServer(t)
		p := newTestCustomOAuthProvider(server.URL, "s3cret")
		p.SetClientAuth(ClientAuth{Method: "client_secret_post"})

		_, err := p.GetOAuthToken(context.Background(), "code")
		require.NoError(t, err)
		require.Len(t, *requests, 1)
		assert.Empty(t, (*requests)[0].authorization)
		assert.Equal(t, "s3cret", (*requests)[0].form.Get("client_secret"))
		assert.Empty(t, (*requests)[0].form.Get("client_assertion"))
	})

	t.Run("client_secret_basic sends the secret in the header only", func(t *testing.T) {
		server, requests := newRecordingTokenServer(t)
		p := newTestCustomOAuthProvider(server.URL, "s3cret")
		p.SetClientAuth(ClientAuth{Method: "client_secret_basic"})

		_, err := p.GetOAuthToken(context.Background(), "code")
		require.NoError(t, err)
		require.Len(t, *requests, 1)
		assert.Contains(t, (*requests)[0].authorization, "Basic ")
		assert.Empty(t, (*requests)[0].form.Get("client_secret"))
	})

	t.Run("unset method keeps the default behaviour", func(t *testing.T) {
		server, requests := newRecordingTokenServer(t)
		p := newTestCustomOAuthProvider(server.URL, "s3cret")

		_, err := p.GetOAuthToken(context.Background(), "code")
		require.NoError(t, err)
		require.Len(t, *requests, 1)
		assert.Contains(t, (*requests)[0].authorization, "Basic ")
	})
}

func TestParseClientSigningKey(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signer, err := ParseClientSigningKey(pemEncodePKCS8(t, ecKey))
	require.NoError(t, err)
	method, err := signingMethodFor(signer)
	require.NoError(t, err)
	assert.Equal(t, "ES256", method.Alg())

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pkcs1 := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}))
	_, err = ParseClientSigningKey(pkcs1)
	require.NoError(t, err)

	weakKey, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	_, err = ParseClientSigningKey(pemEncodePKCS8(t, weakKey))
	assert.ErrorContains(t, err, "at least 2048 bits")

	_, err = ParseClientSigningKey("not a key")
	assert.ErrorContains(t, err, "not PEM encoded")

	_, err = NewClientAuth("private_key_jwt", "", "")
	assert.Error(t, err)

	_, err = NewClientAuth("tls_client_auth", "", "")
	assert.ErrorContains(t, err, "unsupported token endpoint auth method")
}

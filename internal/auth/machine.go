package auth

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/retyc/retyc-cli/internal/config"
	"github.com/retyc/retyc-cli/internal/machinekey"
	"golang.org/x/oauth2"
)

// ErrMachineRevoked is wrapped when the identity provider refuses the
// credentials of a machine account: it was disabled or deleted, or its key
// was removed. Nothing the machine can do fixes it.
var ErrMachineRevoked = errors.New("machine account refused by the identity provider (disabled or deleted?)")

// machineRenewMargin is how long before its expiry a token is renewed.
const machineRenewMargin = 30 * time.Second

// machineDefaultLifetime is the expiry given to a token answered without
// expires_in: the access token lifespan of machine clients (backend spec §8.1).
const machineDefaultLifetime = 300 * time.Second

// MachineTokenSource is an oauth2.TokenSource for a machine account: it
// obtains access tokens with the client_credentials grant, authenticating
// with a signed JWT assertion (RFC 7523). There is no refresh token: a new
// token is requested when the cached one is about to expire. It is safe for
// concurrent use.
type MachineTokenSource struct {
	mu         sync.Mutex
	tok        *oauth2.Token
	key        *ecdsa.PrivateKey
	kid        string
	clientID   string
	endpoint   string
	httpClient *http.Client
	now        func() time.Time
}

// NewMachineTokenSource reads the signing key of m and returns its token
// source. httpClient must be built on api.BaseTransport. A key that cannot be
// read or parsed wraps config.ErrMachineConfig.
func NewMachineTokenSource(m *config.Machine, httpClient *http.Client) (*MachineTokenSource, error) {
	data, err := config.ReadMachineFile(m.ClientKeyFile)
	if err != nil {
		return nil, err
	}
	key, err := machinekey.ParseSigningKey(data)
	if err != nil {
		return nil, fmt.Errorf("%w: reading %s: %w", config.ErrMachineConfig, m.ClientKeyFile, err)
	}

	return &MachineTokenSource{
		key:        key,
		kid:        machinekey.Thumbprint(&key.PublicKey),
		clientID:   m.ClientID,
		endpoint:   m.TokenEndpoint,
		httpClient: httpClient,
		now:        time.Now,
	}, nil
}

// Token returns a valid access token, requesting a new one when fewer than 30
// seconds remain on the cached one.
func (s *MachineTokenSource) Token() (*oauth2.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.tok != nil && s.tok.Expiry.Sub(s.now()) > machineRenewMargin {
		return s.tok, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tok, err := s.request(ctx)
	if err != nil {
		return nil, err
	}
	s.tok = tok

	return tok, nil
}

// Expire makes the next call to Token request a new access token, for a
// caller the API has just answered 401.
func (s *MachineTokenSource) Expire() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.tok = nil
}

// request performs one client_credentials exchange. Errors never carry the
// assertion, the key or the answer's body.
func (s *MachineTokenSource) request(ctx context.Context) (*oauth2.Token, error) {
	now := s.now()
	assertion, err := machinekey.SignAssertion(s.key, s.kid, s.clientID, s.endpoint, now)
	if err != nil {
		return nil, fmt.Errorf("signing machine assertion: %w", err)
	}
	form := url.Values{
		"grant_type":            {"client_credentials"},
		"client_id":             {s.clientID},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("machine token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("machine token request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading machine token response: %w", err)
	}
	var tr TokenResponse
	decodeErr := json.Unmarshal(body, &tr)

	if tr.Error != "" || resp.StatusCode >= http.StatusBadRequest {
		refused := &RefreshError{Status: resp.StatusCode, Code: tr.Error, Description: tr.ErrorDesc}
		switch tr.Error {
		case "invalid_client", "unauthorized_client", "invalid_grant":
			return nil, fmt.Errorf("machine token request: %w: %w", ErrMachineRevoked, refused)
		}

		return nil, fmt.Errorf("machine token request: %w", refused)
	}
	if decodeErr != nil || tr.AccessToken == "" {
		return nil, fmt.Errorf("machine token response (status %d) is not a token", resp.StatusCode)
	}

	tok := &oauth2.Token{AccessToken: tr.AccessToken, TokenType: tr.TokenType}
	// An answer without expires_in still gets an expiry, so the token is
	// cached instead of requested again for every API call.
	lifetime := machineDefaultLifetime
	if tr.ExpiresIn > 0 {
		lifetime = time.Duration(tr.ExpiresIn) * time.Second
	}
	tok.Expiry = now.Add(lifetime)

	return tok, nil
}

package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"filippo.io/age"

	"github.com/retyc/retyc-cli/core/api"
	"github.com/retyc/retyc-cli/core/auth"
	"github.com/retyc/retyc-cli/core/config"
	"github.com/retyc/retyc-cli/core/machinekey"
)

// machineConfig returns a configuration whose machine account holds id, built
// from bytes as an importer does (no file, no environment).
func machineConfig(t *testing.T, clientID, tokenEndpoint string, id *age.HybridIdentity) *config.Config {
	t.Helper()
	key, err := machinekey.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	pemData, err := machinekey.MarshalSigningKey(key)
	if err != nil {
		t.Fatal(err)
	}
	m, err := config.NewMachineIdentity(clientID, tokenEndpoint, pemData, []byte(id.String()+"\n"))
	if err != nil {
		t.Fatalf("NewMachineIdentity() error = %v", err)
	}

	return &config.Config{Machine: m}
}

func failingReader(t *testing.T) PassphraseReader {
	t.Helper()

	return func() (string, error) {
		t.Error("passphrase reader called in machine mode")

		return "", errors.New("unexpected")
	}
}

func TestResolveUserIdentityMachine(t *testing.T) {
	id := mustKeyPair(t)
	cfg := machineConfig(t, "c1", "https://idp.example/token", id)
	cfg.Keyring.Enabled = true // must not be consulted

	got, err := ResolveUserIdentity(context.Background(), cfg,
		&api.UserKey{PublicKey: id.Recipient().String()}, failingReader(t))
	if err != nil {
		t.Fatalf("ResolveUserIdentity() error = %v", err)
	}
	if got.Recipient().String() != id.Recipient().String() {
		t.Error("identity does not match the age.key")
	}
}

func TestMachineIdentityMismatch(t *testing.T) {
	id, other := mustKeyPair(t), mustKeyPair(t)
	cfg := machineConfig(t, "c1", "https://idp.example/token", id)

	_, err := MachineIdentity(context.Background(), cfg.Machine, &api.UserKey{PublicKey: other.Recipient().String()})
	if !errors.Is(err, ErrAgeKeyMismatch) || !errors.Is(err, config.ErrMachineConfig) {
		t.Fatalf("err = %v, want ErrAgeKeyMismatch and ErrMachineConfig", err)
	}
}

func TestMachineIdentityNoActiveKey(t *testing.T) {
	cfg := machineConfig(t, "c1", "https://idp.example/token", mustKeyPair(t))

	_, err := MachineIdentity(context.Background(), cfg.Machine, nil)
	if !errors.Is(err, config.ErrMachineConfig) || !strings.Contains(err.Error(), "no active key") {
		t.Fatalf("err = %v", err)
	}
}

func TestMachineIdentityNotMachine(t *testing.T) {
	_, err := MachineIdentity(context.Background(), nil, &api.UserKey{PublicKey: "age1pq1x"})
	if !errors.Is(err, config.ErrMachineConfig) || !strings.Contains(err.Error(), "not in machine mode") {
		t.Fatalf("err = %v", err)
	}
}

func TestUnlockUserIdentityMachine(t *testing.T) {
	id := mustKeyPair(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"k1","public_key":"` + id.Recipient().String() + `","private_key_enc":null}`))
	}))
	defer srv.Close()
	cfg := machineConfig(t, "c1", "https://idp.example/token", id)

	got, err := UnlockUserIdentity(context.Background(), cfg, newKeyTestClient(srv), failingReader(t))
	if err != nil {
		t.Fatalf("UnlockUserIdentity() error = %v", err)
	}
	if got.Recipient().String() != id.Recipient().String() {
		t.Error("identity mismatch")
	}
}

func TestUnlockUserIdentityMachineNoActiveKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(nil)
	}))
	defer srv.Close()
	cfg := machineConfig(t, "c1", "https://idp.example/token", mustKeyPair(t))

	_, err := UnlockUserIdentity(context.Background(), cfg, newKeyTestClient(srv), failingReader(t))
	if !errors.Is(err, config.ErrMachineConfig) {
		t.Fatalf("err = %v, want ErrMachineConfig", err)
	}
}

func TestUnlockUserIdentityMachineMismatch(t *testing.T) {
	id, other := mustKeyPair(t), mustKeyPair(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"k1","public_key":"` + other.Recipient().String() + `","private_key_enc":null}`))
	}))
	defer srv.Close()
	cfg := machineConfig(t, "c1", "https://idp.example/token", id)

	_, err := UnlockUserIdentity(context.Background(), cfg, newKeyTestClient(srv), failingReader(t))
	if !errors.Is(err, ErrAgeKeyMismatch) || !errors.Is(err, config.ErrMachineConfig) {
		t.Fatalf("err = %v, want ErrAgeKeyMismatch and ErrMachineConfig", err)
	}
}

// machineTenant fakes the identity provider and the API of one machine
// account: the token endpoint issues token, the API accepts only that token
// and answers the account's active key.
type machineTenant struct {
	t     *testing.T
	token string
	key   *age.HybridIdentity
	org   *age.HybridIdentity

	mu      sync.Mutex
	creates []map[string]any
}

func (m *machineTenant) handler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/token" {
		_ = r.ParseForm()
		if r.PostForm.Get("client_assertion") == "" {
			m.t.Error("token request without a client assertion")
		}
		_, _ = fmt.Fprintf(w, `{"access_token":%q,"token_type":"Bearer","expires_in":300}`, m.token)

		return
	}
	if got := r.Header.Get("Authorization"); got != "Bearer "+m.token {
		m.t.Errorf("%s %s: Authorization = %q, want the token of this tenant", r.Method, r.URL.Path, got)
		w.WriteHeader(http.StatusUnauthorized)

		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/user/me/key/active":
		_ = json.NewEncoder(w).Encode(api.UserKey{ID: "k-" + m.token, PublicKey: m.key.Recipient().String()})
	case r.Method == http.MethodGet && r.URL.Path == "/organization/service-account":
		_ = json.NewEncoder(w).Encode(serviceAccountJSON("active", m.org))
	case r.Method == http.MethodPost && r.URL.Path == "/dataroom":
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		m.mu.Lock()
		m.creates = append(m.creates, body)
		m.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(api.Dataroom{ID: "dr-" + m.token, Title: "T"})
	default:
		m.t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	}
}

// Two machine identities live side by side in one process, as in a
// multi-tenant importer: each has its own Config and client, nothing comes
// from the environment, and neither sees the other's keys or tokens.
func TestMachineIdentitiesInParallel(t *testing.T) {
	t.Parallel()
	for i := range 2 {
		t.Run(fmt.Sprintf("tenant%d", i), func(t *testing.T) {
			t.Parallel()
			tenant := &machineTenant{t: t, token: fmt.Sprintf("at-%d", i), key: mustKeyPair(t), org: mustKeyPair(t)}
			srv := httptest.NewServer(http.HandlerFunc(tenant.handler))
			t.Cleanup(srv.Close)

			cfg := machineConfig(t, fmt.Sprintf("client-%d", i), srv.URL+"/token", tenant.key)
			src := auth.NewMachineTokenSource(cfg.Machine, srv.Client())
			client := api.New(srv.URL, "retyc-test/1.0", src, false, false)
			ctx := context.Background()

			var wg sync.WaitGroup
			for range 4 {
				wg.Go(func() {
					got, err := UnlockUserIdentity(ctx, cfg, client, failingReader(t))
					if err != nil {
						t.Errorf("UnlockUserIdentity() error = %v", err)

						return
					}
					if got.Recipient().String() != tenant.key.Recipient().String() {
						t.Error("UnlockUserIdentity() returned another tenant's identity")
					}
					got, err = ResolveActiveUserIdentity(ctx, cfg, client, failingReader(t))
					if err != nil || got.Recipient().String() != tenant.key.Recipient().String() {
						t.Errorf("ResolveActiveUserIdentity() = %v, want this tenant's identity", err)
					}
					res, err := CreateDataroom(ctx, cfg, client, "T", api.DataroomOptions{}, failingReader(t))
					if err != nil || res.ID != "dr-"+tenant.token {
						t.Errorf("CreateDataroom() = %+v, %v", res, err)
					}
				})
			}
			wg.Wait()

			tenant.mu.Lock()
			defer tenant.mu.Unlock()
			if len(tenant.creates) != 4 {
				t.Fatalf("POST /dataroom calls = %d, want 4", len(tenant.creates))
			}
			for _, body := range tenant.creates {
				assertOpens(t, body, tenant.key, "machine")
				assertOpens(t, body, tenant.org, "organization")
			}
		})
	}
}

package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/oauth2"

	"github.com/retyc/retyc-cli/pkg/api"
	"github.com/retyc/retyc-cli/pkg/config"
	"github.com/retyc/retyc-cli/pkg/crypto"
	"github.com/retyc/retyc-cli/pkg/crypto/cryptotest"
	"github.com/retyc/retyc-cli/pkg/service"
	"github.com/retyc/retyc-cli/pkg/vfs"
)

// newStartupTestServer serves the two endpoints hit at webdav serve startup:
// the dataroom listing (connectivity check) and the user's active key, whose
// private half is encrypted under keyPassphrase.
func newStartupTestServer(t *testing.T, keyPassphrase string) *httptest.Server {
	t.Helper()
	userKey, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	userPrivEnc, err := cryptotest.EncryptWithPassphrase([]byte(userKey.String()), keyPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dataroom":
			_, _ = io.WriteString(w, `{"items":[],"total":0}`)
		case "/user/me/key/active":
			_, _ = fmt.Fprintf(w, `{"id":"k1","public_key":%q,"private_key_enc":%q}`,
				userKey.Recipient().String(), userPrivEnc)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	return srv
}

func newStartupTestClient(srv *httptest.Server) *api.Client {
	return api.New(srv.URL, "retyc-test/1.0",
		oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test", TokenType: "Bearer"}), false, false)
}

func TestWebdavStartupCheck_OK(t *testing.T) {
	srv := newStartupTestServer(t, "good-pw")

	identity, err := serveStartupCheck(context.Background(), &config.Config{}, newStartupTestClient(srv),
		func() (string, error) { return "good-pw", nil })
	if err != nil {
		t.Fatalf("serveStartupCheck() error = %v, want nil", err)
	}
	if identity == nil {
		t.Fatal("serveStartupCheck() returned a nil identity")
	}
}

func TestWebdavStartupCheck_WrongPassphrase(t *testing.T) {
	srv := newStartupTestServer(t, "good-pw")

	_, err := serveStartupCheck(context.Background(), &config.Config{}, newStartupTestClient(srv), func() (string, error) {
		return "bad-pw", nil
	})
	if err == nil || !strings.Contains(err.Error(), "wrong key passphrase") {
		t.Fatalf("serveStartupCheck() error = %v, want wrong key passphrase", err)
	}
}

// A wrong passphrase set in the environment fails at startup.
func TestWebdavStartupCheck_WrongEnvPassphrase(t *testing.T) {
	srv := newStartupTestServer(t, "good-pw")
	t.Setenv(config.EnvKeyPassphraseName, "bad-pw")
	cfg := &config.Config{}

	_, err := serveStartupCheck(context.Background(), cfg, newStartupTestClient(srv), func() (string, error) {
		return config.KeyPassphrase(), nil
	})
	if !errors.Is(err, service.ErrWrongKeyPassphrase) {
		t.Fatalf("serveStartupCheck() error = %v, want ErrWrongKeyPassphrase", err)
	}
}

// Without the environment, the reader (the prompt) is asked once.
func TestWebdavStartupCheck_PromptWithoutEnv(t *testing.T) {
	srv := newStartupTestServer(t, "good-pw")
	t.Setenv(config.EnvKeyPassphraseName, "")
	calls := 0

	identity, err := serveStartupCheck(context.Background(), &config.Config{}, newStartupTestClient(srv),
		func() (string, error) {
			calls++

			return "good-pw", nil
		})
	if err != nil || identity == nil {
		t.Fatalf("serveStartupCheck() = %v, %v, want an identity", identity, err)
	}
	if calls != 1 {
		t.Fatalf("reader called %d times, want 1", calls)
	}
}

func TestWebdavStartupCheck_APIUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)

	_, err := serveStartupCheck(context.Background(), &config.Config{}, newStartupTestClient(srv), func() (string, error) {
		return "good-pw", nil
	})
	if err == nil || !strings.Contains(err.Error(), "API connectivity check failed") {
		t.Fatalf("serveStartupCheck() error = %v, want connectivity failure", err)
	}
}

// — Directory invalidation ————————————————————————————————————————————————————

// — vfs defaults ——————————————————————————————————————————————————————————————

// vfs cannot import pkg/config: its fallback TTL is a copy of the
// configuration default, and the two must not drift apart.
func TestVFSDefaultCacheTTLMatchesConfig(t *testing.T) {
	if vfs.DefaultCacheTTL != config.DefaultCacheTTL {
		t.Errorf("vfs.DefaultCacheTTL = %v, config.DefaultCacheTTL = %v",
			vfs.DefaultCacheTTL, config.DefaultCacheTTL)
	}
}

// Same for the negative cache: vfs.DefaultNegativeTTL is what an FS built
// outside a command passes, cache.negative_ttl what the commands pass.
func TestVFSDefaultNegativeTTLMatchesConfig(t *testing.T) {
	if vfs.DefaultNegativeTTL != config.DefaultCacheNegativeTTL {
		t.Errorf("vfs.DefaultNegativeTTL = %v, config.DefaultCacheNegativeTTL = %v",
			vfs.DefaultNegativeTTL, config.DefaultCacheNegativeTTL)
	}
}

// Same for the number of background refreshes: webdav serve passes
// api.concurrency.list, and an FS built without it must not differ.
func TestVFSDefaultListConcurrencyMatchesConfig(t *testing.T) {
	if vfs.DefaultListConcurrency != config.DefaultConcurrency {
		t.Errorf("vfs.DefaultListConcurrency = %d, config.DefaultConcurrency = %d",
			vfs.DefaultListConcurrency, config.DefaultConcurrency)
	}
}

func TestVFSDefaultUploadConcurrencyMatchesConfig(t *testing.T) {
	if vfs.DefaultUploadConcurrency != config.DefaultConcurrency {
		t.Errorf("vfs.DefaultUploadConcurrency = %d, config.DefaultConcurrency = %d",
			vfs.DefaultUploadConcurrency, config.DefaultConcurrency)
	}
}

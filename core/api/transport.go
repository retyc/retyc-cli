package api

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Standard OpenSSL environment variables for a custom trust store. Go honours
// them natively on Linux only; reading them here makes the behaviour identical
// on macOS and Windows.
const (
	certFileEnv = "SSL_CERT_FILE"
	certDirEnv  = "SSL_CERT_DIR"
)

// tlsRoots holds the certificate pool shared by every TLS client of the CLI.
// A nil pool means "use the platform default trust store".
var tlsRoots *x509.CertPool

// InitTLSRoots loads the root CAs named by SSL_CERT_FILE and SSL_CERT_DIR and
// adds them to the platform trust store rather than replacing it, so a
// corporate CA can be trusted without losing the public ones. It returns a
// human-readable description of where the roots came from, for --debug.
//
// Loading once at startup makes an unreadable or invalid bundle fail
// immediately instead of in the middle of a transfer.
func InitTLSRoots() (string, error) {
	certFile := os.Getenv(certFileEnv)
	certDirs := os.Getenv(certDirEnv)

	if certFile == "" && certDirs == "" {
		tlsRoots = nil

		return "system", nil
	}

	system, err := platformRoots(x509.SystemCertPool)
	if err != nil {
		return "", fmt.Errorf("loading system certificate pool: %w", err)
	}

	pool, err := loadRootCAs(system, certFile, certDirs)
	if err != nil {
		return "", err
	}

	tlsRoots = pool

	sources := []string{"system"}
	if certFile != "" {
		sources = append(sources, certFileEnv+"="+certFile)
	}

	if certDirs != "" {
		sources = append(sources, certDirEnv+"="+certDirs)
	}

	return strings.Join(sources, " + "), nil
}

// platformRoots loads the platform trust store as if SSL_CERT_FILE and
// SSL_CERT_DIR were not set, then restores them.
//
// On Linux x509.SystemCertPool() reads those two variables itself, and they
// REPLACE the default certificate file and directory lists rather than adding
// to them. Loading the pool with them still set would therefore return a store
// holding nothing but the custom CAs, and adding those CAs on top would leave
// the public roots out — the opposite of what the caller asks for.
//
// This must run before anything else in the process calls
// x509.SystemCertPool(), which caches its result on first use.
func platformRoots(load func() (*x509.CertPool, error)) (*x509.CertPool, error) {
	for _, name := range []string{certFileEnv, certDirEnv} {
		if value, ok := os.LookupEnv(name); ok {
			defer func() { _ = os.Setenv(name, value) }()

			if err := os.Unsetenv(name); err != nil {
				return nil, fmt.Errorf("hiding %s: %w", name, err)
			}
		}
	}

	return load()
}

// loadRootCAs returns a copy of base extended with the certificates found in
// certFile and in each directory of certDirs. It returns a nil pool when
// neither is set, meaning the caller should keep the platform default.
// base is never modified.
func loadRootCAs(base *x509.CertPool, certFile, certDirs string) (*x509.CertPool, error) {
	if certFile == "" && certDirs == "" {
		return nil, nil
	}

	pool := x509.NewCertPool()
	if base != nil {
		pool = base.Clone()
	}

	added := 0

	if certFile != "" {
		data, err := os.ReadFile(certFile) //nolint:gosec // G304/G703: path comes from the user's own environment
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", certFileEnv, err)
		}

		if !pool.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("%s=%s holds no PEM certificate", certFileEnv, certFile)
		}

		added++
	}

	for _, dir := range filepath.SplitList(certDirs) {
		if dir == "" {
			continue
		}

		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", certDirEnv, err)
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			// Files that are not certificates are skipped, as OpenSSL does.
			//nolint:gosec // G304/G703: path comes from the user's own environment
			data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				continue
			}

			if pool.AppendCertsFromPEM(data) {
				added++
			}
		}
	}

	if added == 0 {
		return nil, fmt.Errorf("no PEM certificate found in %s=%s", certDirEnv, certDirs)
	}

	return pool, nil
}

// ProxyLabel describes the proxy a request goes through, for --debug output.
// It returns an empty string when the request does not go through a proxy.
func ProxyLabel(req *http.Request) string {
	proxyURL, err := http.ProxyFromEnvironment(req)
	if err != nil {
		return ""
	}

	return proxyLabel(proxyURL)
}

// proxyLabel formats a proxy URL with its credentials redacted, so --debug
// output stays safe to paste into a bug report.
func proxyLabel(proxyURL *url.URL) string {
	if proxyURL == nil {
		return ""
	}

	return " (via proxy " + proxyURL.Redacted() + ")"
}

// BaseTransport returns the transport shared by every HTTP client of the CLI:
// proxy settings from the environment (HTTP_PROXY, HTTPS_PROXY, NO_PROXY) and
// the root CAs loaded by InitTLSRoots. When insecure is true, TLS certificate
// verification is skipped.
//
// Callers may tune the returned transport (timeouts, ...) before use.
func BaseTransport(insecure bool) *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			RootCAs:            tlsRoots,
			InsecureSkipVerify: insecure, // #nosec G402 — intentional, controlled by --insecure flag
			MinVersion:         tls.VersionTLS12,
		},
		ForceAttemptHTTP2: true,
	}
}

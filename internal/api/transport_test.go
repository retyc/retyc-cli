package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// testCA is a self-signed CA plus a leaf certificate it issued, so tests can
// assert on real verification behaviour instead of poking at pool internals.
type testCA struct {
	PEM  []byte
	Leaf *x509.Certificate
}

func newTestCA(t *testing.T, commonName string) testCA {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: commonName + "-leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"leaf.example"},
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	return testCA{
		PEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		Leaf: leaf,
	}
}

// trusts reports whether pool accepts the leaf issued by the matching CA.
func trusts(pool *x509.CertPool, leaf *x509.Certificate) bool {
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:       pool,
		DNSName:     "leaf.example",
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		CurrentTime: time.Now(),
	})

	return err == nil
}

func writeCAFile(t *testing.T, dir, name string, ca testCA) string {
	t.Helper()

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, ca.PEM, 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

func TestLoadRootCAs_NoEnvKeepsPlatformDefault(t *testing.T) {
	pool, err := loadRootCAs(x509.NewCertPool(), "", "")
	if err != nil {
		t.Fatalf("loadRootCAs() error = %v", err)
	}

	if pool != nil {
		t.Error("pool = non-nil, want nil so the platform default pool is used")
	}
}

func TestLoadRootCAs_CertFileIsTrusted(t *testing.T) {
	ca := newTestCA(t, "corp-file")
	path := writeCAFile(t, t.TempDir(), "corp.pem", ca)

	pool, err := loadRootCAs(x509.NewCertPool(), path, "")
	if err != nil {
		t.Fatalf("loadRootCAs() error = %v", err)
	}

	if !trusts(pool, ca.Leaf) {
		t.Error("pool does not trust the certificate from SSL_CERT_FILE")
	}
}

func TestLoadRootCAs_KeepsBaseRoots(t *testing.T) {
	system := newTestCA(t, "system")
	corp := newTestCA(t, "corp")

	base := x509.NewCertPool()
	if !base.AppendCertsFromPEM(system.PEM) {
		t.Fatal("could not seed the base pool")
	}

	path := writeCAFile(t, t.TempDir(), "corp.pem", corp)

	pool, err := loadRootCAs(base, path, "")
	if err != nil {
		t.Fatalf("loadRootCAs() error = %v", err)
	}

	if !trusts(pool, corp.Leaf) {
		t.Error("pool does not trust the certificate from SSL_CERT_FILE")
	}

	if !trusts(pool, system.Leaf) {
		t.Error("pool dropped the base roots — SSL_CERT_FILE must add to them, not replace them")
	}
}

func TestLoadRootCAs_DoesNotMutateBasePool(t *testing.T) {
	corp := newTestCA(t, "corp")
	base := x509.NewCertPool()
	path := writeCAFile(t, t.TempDir(), "corp.pem", corp)

	if _, err := loadRootCAs(base, path, ""); err != nil {
		t.Fatalf("loadRootCAs() error = %v", err)
	}

	if trusts(base, corp.Leaf) {
		t.Error("base pool was mutated — the shared system pool must be left untouched")
	}
}

func TestLoadRootCAs_MissingCertFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.pem")

	_, err := loadRootCAs(x509.NewCertPool(), missing, "")
	if err == nil {
		t.Fatal("loadRootCAs() error = nil, want an error for a missing SSL_CERT_FILE")
	}

	if !strings.Contains(err.Error(), missing) {
		t.Errorf("error = %q, want it to name the missing file", err)
	}
}

func TestLoadRootCAs_CertFileWithoutCertificate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "garbage.pem")

	if err := os.WriteFile(path, []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := loadRootCAs(x509.NewCertPool(), path, ""); err == nil {
		t.Fatal("loadRootCAs() error = nil, want an error for a file holding no certificate")
	}
}

func TestLoadRootCAs_CertDirIsTrusted(t *testing.T) {
	ca := newTestCA(t, "corp-dir")
	dir := t.TempDir()
	writeCAFile(t, dir, "corp.pem", ca)

	pool, err := loadRootCAs(x509.NewCertPool(), "", dir)
	if err != nil {
		t.Fatalf("loadRootCAs() error = %v", err)
	}

	if !trusts(pool, ca.Leaf) {
		t.Error("pool does not trust the certificate from SSL_CERT_DIR")
	}
}

func TestLoadRootCAs_CertDirIgnoresNonCertificateFiles(t *testing.T) {
	ca := newTestCA(t, "corp-dir")
	dir := t.TempDir()
	writeCAFile(t, dir, "corp.pem", ca)

	if err := os.WriteFile(filepath.Join(dir, "README"), []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	pool, err := loadRootCAs(x509.NewCertPool(), "", dir)
	if err != nil {
		t.Fatalf("loadRootCAs() error = %v", err)
	}

	if !trusts(pool, ca.Leaf) {
		t.Error("a non-certificate file in SSL_CERT_DIR must be skipped, not fatal")
	}
}

func TestLoadRootCAs_MultipleCertDirs(t *testing.T) {
	first := newTestCA(t, "first")
	second := newTestCA(t, "second")

	dirA := t.TempDir()
	dirB := t.TempDir()
	writeCAFile(t, dirA, "a.pem", first)
	writeCAFile(t, dirB, "b.pem", second)

	pool, err := loadRootCAs(x509.NewCertPool(), "", dirA+string(os.PathListSeparator)+dirB)
	if err != nil {
		t.Fatalf("loadRootCAs() error = %v", err)
	}

	if !trusts(pool, first.Leaf) {
		t.Error("pool does not trust the CA from the first SSL_CERT_DIR entry")
	}

	if !trusts(pool, second.Leaf) {
		t.Error("pool does not trust the CA from the second SSL_CERT_DIR entry")
	}
}

func TestLoadRootCAs_MissingCertDir(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent")

	_, err := loadRootCAs(x509.NewCertPool(), "", missing)
	if err == nil {
		t.Fatal("loadRootCAs() error = nil, want an error for a missing SSL_CERT_DIR")
	}
}

func TestLoadRootCAs_EmptyCertDir(t *testing.T) {
	if _, err := loadRootCAs(x509.NewCertPool(), "", t.TempDir()); err == nil {
		t.Fatal("loadRootCAs() error = nil, want an error when SSL_CERT_DIR holds no certificate")
	}
}

func TestInitTLSRoots_TrustsCertFile(t *testing.T) {
	ca := newTestCA(t, "init")
	path := writeCAFile(t, t.TempDir(), "corp.pem", ca)

	t.Setenv(certFileEnv, path)
	t.Setenv(certDirEnv, "")
	t.Cleanup(func() { tlsRoots = nil })

	source, err := InitTLSRoots()
	if err != nil {
		t.Fatalf("InitTLSRoots() error = %v", err)
	}

	if !strings.Contains(source, certFileEnv) {
		t.Errorf("source = %q, want it to mention %s", source, certFileEnv)
	}

	roots := BaseTransport(false).TLSClientConfig.RootCAs
	if !trusts(roots, ca.Leaf) {
		t.Error("BaseTransport does not use the roots loaded by InitTLSRoots")
	}
}

func TestInitTLSRoots_InvalidBundleFails(t *testing.T) {
	t.Setenv(certFileEnv, filepath.Join(t.TempDir(), "absent.pem"))
	t.Setenv(certDirEnv, "")
	t.Cleanup(func() { tlsRoots = nil })

	if _, err := InitTLSRoots(); err == nil {
		t.Fatal("InitTLSRoots() error = nil, want an error for an unreadable bundle")
	}
}

func TestInitTLSRoots_NoEnvReportsSystemSource(t *testing.T) {
	t.Setenv(certFileEnv, "")
	t.Setenv(certDirEnv, "")
	t.Cleanup(func() { tlsRoots = nil })

	source, err := InitTLSRoots()
	if err != nil {
		t.Fatalf("InitTLSRoots() error = %v", err)
	}

	if source != "system" {
		t.Errorf("source = %q, want \"system\"", source)
	}

	if tlsRoots != nil {
		t.Error("tlsRoots = non-nil, want nil so the platform default pool is used")
	}
}

func TestBaseTransport_UsesEnvironmentProxy(t *testing.T) {
	// http.ProxyFromEnvironment caches the environment on first use, so the
	// honest assertion is that the transport delegates to it at all.
	got := reflect.ValueOf(BaseTransport(false).Proxy).Pointer()
	want := reflect.ValueOf(http.ProxyFromEnvironment).Pointer()

	if got != want {
		t.Error("Proxy is not http.ProxyFromEnvironment — HTTP_PROXY/HTTPS_PROXY/NO_PROXY would be ignored")
	}
}

func TestBaseTransport_Insecure(t *testing.T) {
	if BaseTransport(false).TLSClientConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify = true, want false by default")
	}

	if !BaseTransport(true).TLSClientConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify = false, want true when insecure is requested")
	}
}

func TestNew_TransportUsesEnvironmentProxyAndRoots(t *testing.T) {
	client := New("https://example.test", "retyc-test/1.0", staticTokenSource(), false, false)

	ua, ok := client.httpClient.Transport.(*UserAgentTransport)
	if !ok {
		t.Fatalf("transport = %T, want *UserAgentTransport", client.httpClient.Transport)
	}

	oauthTransport, ok := ua.Base.(*oauth2.Transport)
	if !ok {
		t.Fatalf("UserAgentTransport.Base = %T, want *oauth2.Transport", ua.Base)
	}

	inner, ok := oauthTransport.Base.(*http.Transport)
	if !ok {
		t.Fatalf("oauth2.Transport.Base = %T, want *http.Transport", oauthTransport.Base)
	}

	if inner.Proxy == nil {
		t.Error("Proxy = nil — the API client would ignore HTTP_PROXY/HTTPS_PROXY/NO_PROXY")
	}

	if inner.ResponseHeaderTimeout == 0 {
		t.Error("ResponseHeaderTimeout = 0, want the API transport tuning to be preserved")
	}
}

// envSnapshot records the SSL_CERT_* variables as seen by the loader.
type envSnapshot struct {
	certFile string
	certDirs string
}

func TestPlatformRoots_HidesCertEnvFromLoader(t *testing.T) {
	t.Setenv(certFileEnv, "/corp/ca.pem")
	t.Setenv(certDirEnv, "/corp/certs")

	var seen envSnapshot

	_, err := platformRoots(func() (*x509.CertPool, error) {
		seen = envSnapshot{certFile: os.Getenv(certFileEnv), certDirs: os.Getenv(certDirEnv)}

		return x509.NewCertPool(), nil
	})
	if err != nil {
		t.Fatalf("platformRoots() error = %v", err)
	}

	// On Linux x509.SystemCertPool() honours these variables and lets them
	// REPLACE the default trust store, which would leave the custom CAs alone
	// in the pool instead of added to it.
	if seen.certFile != "" || seen.certDirs != "" {
		t.Errorf("loader saw %s=%q %s=%q, want both hidden",
			certFileEnv, seen.certFile, certDirEnv, seen.certDirs)
	}
}

func TestPlatformRoots_RestoresEnv(t *testing.T) {
	t.Setenv(certFileEnv, "/corp/ca.pem")
	t.Setenv(certDirEnv, "/corp/certs")

	if _, err := platformRoots(func() (*x509.CertPool, error) {
		return x509.NewCertPool(), nil
	}); err != nil {
		t.Fatalf("platformRoots() error = %v", err)
	}

	if got := os.Getenv(certFileEnv); got != "/corp/ca.pem" {
		t.Errorf("%s = %q after the call, want it restored", certFileEnv, got)
	}

	if got := os.Getenv(certDirEnv); got != "/corp/certs" {
		t.Errorf("%s = %q after the call, want it restored", certDirEnv, got)
	}
}

func TestPlatformRoots_RestoresEnvWhenLoaderFails(t *testing.T) {
	t.Setenv(certFileEnv, "/corp/ca.pem")

	if _, err := platformRoots(func() (*x509.CertPool, error) {
		return nil, errors.New("boom")
	}); err == nil {
		t.Fatal("platformRoots() error = nil, want the loader error to propagate")
	}

	if got := os.Getenv(certFileEnv); got != "/corp/ca.pem" {
		t.Errorf("%s = %q after a failed load, want it restored", certFileEnv, got)
	}
}

func TestPlatformRoots_DoesNotCreateUnsetVariables(t *testing.T) {
	t.Setenv(certFileEnv, "placeholder")
	os.Unsetenv(certFileEnv) //nolint:errcheck // restored by t.Setenv cleanup

	if _, err := platformRoots(func() (*x509.CertPool, error) {
		return x509.NewCertPool(), nil
	}); err != nil {
		t.Fatalf("platformRoots() error = %v", err)
	}

	if _, ok := os.LookupEnv(certFileEnv); ok {
		t.Errorf("%s exists after the call, want it left unset", certFileEnv)
	}
}

func TestInitTLSRoots_KeepsSystemRootsWhenBothVariablesAreSet(t *testing.T) {
	corp := newTestCA(t, "corp-both")
	dir := t.TempDir()
	path := writeCAFile(t, dir, "corp.pem", corp)

	t.Setenv(certFileEnv, path)
	t.Setenv(certDirEnv, dir)
	t.Cleanup(func() { tlsRoots = nil })

	if _, err := InitTLSRoots(); err != nil {
		t.Fatalf("InitTLSRoots() error = %v", err)
	}

	if !trusts(tlsRoots, corp.Leaf) {
		t.Fatal("pool does not trust the custom CA")
	}

	// The platform trust store must survive both variables being set together.
	// Only Linux is concerned: it is the one platform where SystemCertPool()
	// reads these variables, and its pool is the only one whose contents can
	// be counted (macOS and Windows return an opaque pool).
	if runtime.GOOS != "linux" {
		t.Skip("SystemCertPool() ignores SSL_CERT_* outside Linux")
	}

	system, err := x509.SystemCertPool()
	if err != nil {
		t.Skipf("no system trust store on this machine: %v", err)
	}

	//nolint:staticcheck // SA1019: no public API counts roots, and the pool is not opaque on Linux
	systemCount := len(system.Subjects())
	if systemCount == 0 {
		t.Skip("empty system trust store, nothing to compare")
	}

	//nolint:staticcheck // SA1019: see above
	if got := len(tlsRoots.Subjects()); got <= systemCount {
		t.Errorf("pool holds %d roots, want more than the %d system roots — the platform trust store was replaced",
			got, systemCount)
	}
}

func TestProxyLabel_RedactsCredentials(t *testing.T) {
	proxyURL, err := url.Parse("http://alice:s3cr3t@proxy.corp:3128")
	if err != nil {
		t.Fatal(err)
	}

	label := proxyLabel(proxyURL)

	if !strings.Contains(label, "proxy.corp:3128") {
		t.Errorf("label = %q, want it to name the proxy host", label)
	}

	if strings.Contains(label, "s3cr3t") {
		t.Errorf("label = %q, leaks the proxy password", label)
	}
}

func TestProxyLabel_NoProxy(t *testing.T) {
	if label := proxyLabel(nil); label != "" {
		t.Errorf("proxyLabel(nil) = %q, want an empty string", label)
	}
}

func TestNew_TransportUsesLoadedRoots(t *testing.T) {
	ca := newTestCA(t, "api-client-roots")

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.PEM) {
		t.Fatal("could not build the test pool")
	}

	previous := tlsRoots
	tlsRoots = pool

	t.Cleanup(func() { tlsRoots = previous })

	client := New("https://example.test", "retyc-test/1.0", staticTokenSource(), false, false)

	ua, ok := client.httpClient.Transport.(*UserAgentTransport)
	if !ok {
		t.Fatalf("transport = %T, want *UserAgentTransport", client.httpClient.Transport)
	}

	oauthTransport, ok := ua.Base.(*oauth2.Transport)
	if !ok {
		t.Fatalf("UserAgentTransport.Base = %T, want *oauth2.Transport", ua.Base)
	}

	inner, ok := oauthTransport.Base.(*http.Transport)
	if !ok {
		t.Fatalf("oauth2.Transport.Base = %T, want *http.Transport", oauthTransport.Base)
	}

	if !trusts(inner.TLSClientConfig.RootCAs, ca.Leaf) {
		t.Error("api.New dropped the custom root CAs")
	}
}

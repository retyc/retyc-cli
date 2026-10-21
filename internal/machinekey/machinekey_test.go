package machinekey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func rfcKey(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	dec := func(s string) *big.Int {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}

		return new(big.Int).SetBytes(b)
	}

	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     dec("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4"),
		Y:     dec("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"),
	}
}

func TestThumbprintRFC7517Key(t *testing.T) {
	got := Thumbprint(rfcKey(t))
	if want := "cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s"; got != want {
		t.Fatalf("thumbprint = %s, want %s", got, want)
	}
}

func TestFingerprintVector(t *testing.T) {
	got := Fingerprint("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", "age1pq1"+strings.Repeat("q", 1200))
	if want := "ESV4-YJGC-56NE-MZDU"; got != want {
		t.Fatalf("fingerprint = %s, want %s", got, want)
	}
}

func TestPublicJWKMembers(t *testing.T) {
	k, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	j := PublicJWK(&k.PublicKey)
	raw, err := json.Marshal(j)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if len(m) != 7 {
		t.Fatalf("members = %v", m)
	}
	for _, name := range []string{"kty", "crv", "x", "y", "kid", "alg", "use"} {
		if _, ok := m[name]; !ok {
			t.Fatalf("missing member %s", name)
		}
	}
	if j.Kid != Thumbprint(&k.PublicKey) || j.Alg != "ES256" || j.Use != "sig" || j.Kty != "EC" || j.Crv != "P-256" {
		t.Fatalf("unexpected jwk %+v", j)
	}
	for _, c := range []string{j.X, j.Y} {
		b, err := base64.RawURLEncoding.DecodeString(c)
		if err != nil || len(b) != 32 {
			t.Fatalf("coordinate %q: len=%d err=%v", c, len(b), err)
		}
	}
}

func TestSigningKeyPEMRoundTrip(t *testing.T) {
	k, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	data, err := MarshalSigningKey(k)
	if err != nil {
		t.Fatal(err)
	}
	if blk, _ := pem.Decode(data); blk == nil || blk.Type != "PRIVATE KEY" {
		t.Fatalf("bad PEM: %s", data)
	}
	back, err := ParseSigningKey(data)
	if err != nil {
		t.Fatal(err)
	}
	if !back.Equal(k) {
		t.Fatal("round trip mismatch")
	}
}

func pemOf(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func TestParseSigningKeyRejectsRSA(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseSigningKey(pemOf(t, k)); err == nil {
		t.Fatal("RSA key accepted")
	}
}

func TestParseSigningKeyRejectsP384(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseSigningKey(pemOf(t, k)); err == nil {
		t.Fatal("P-384 key accepted")
	}
}

func TestParseSigningKeyRejectsGarbage(t *testing.T) {
	if _, err := ParseSigningKey([]byte("not pem")); err == nil {
		t.Fatal("garbage accepted")
	}
}

func part(t *testing.T, s string) map[string]any {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}

	return m
}

func TestSignAssertion(t *testing.T) {
	k, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	tok, err := SignAssertion(k, "kid1", "client", "https://kc/token", now)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("parts = %d", len(parts))
	}
	hdr := part(t, parts[0])
	if len(hdr) != 3 || hdr["alg"] != "ES256" || hdr["kid"] != "kid1" || hdr["typ"] != "JWT" {
		t.Fatalf("header = %v", hdr)
	}
	cl := part(t, parts[1])
	if cl["iss"] != "client" || cl["sub"] != "client" || cl["aud"] != "https://kc/token" {
		t.Fatalf("claims = %v", cl)
	}
	if cl["iat"] != float64(now.Unix()) || cl["exp"] != float64(now.Unix()+30) {
		t.Fatalf("times = %v", cl)
	}
	jti, _ := cl["jti"].(string)
	if len(jti) != 32 {
		t.Fatalf("jti = %q", jti)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		t.Fatalf("sig len=%d err=%v", len(sig), err)
	}
	h := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(&k.PublicKey, h[:], r, s) {
		t.Fatal("signature does not verify")
	}
	tok2, err := SignAssertion(k, "kid1", "client", "https://kc/token", now)
	if err != nil {
		t.Fatal(err)
	}
	if part(t, strings.Split(tok2, ".")[1])["jti"] == jti {
		t.Fatal("jti repeated")
	}
}

func TestSignRotationProof(t *testing.T) {
	k, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	tok, err := SignRotationProof(k, "kid-1", "client-1", "age1pq1abc", now)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("segments = %d, want 3", len(parts))
	}
	hdr, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	if string(hdr) != `{"alg":"ES256","kid":"kid-1"}` {
		t.Fatalf("header = %s", hdr)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	if claims["sub"] != "client-1" || claims["aud"] != RotationAudience || claims["age_recipient"] != "age1pq1abc" {
		t.Fatalf("claims = %v", claims)
	}
	iat, ok1 := claims["iat"].(float64)
	exp, ok2 := claims["exp"].(float64)
	if !ok1 || !ok2 || int64(iat) != now.Unix() || int64(exp-iat) != 120 {
		t.Fatalf("iat/exp = %v/%v", claims["iat"], claims["exp"])
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		t.Fatalf("signature len %d err %v", len(sig), err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(&k.PublicKey, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("signature does not verify")
	}
}

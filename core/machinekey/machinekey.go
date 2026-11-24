// Package machinekey holds the crypto of machine accounts: the ES256 signing
// key used for private_key_jwt, its public JWK, the enrollment fingerprint and
// the client assertion. It depends on the standard library only.
package machinekey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	pemType        = "PRIVATE KEY"
	assertionTTL   = 30 * time.Second
	coordinateSize = 32
	fingerprintTag = "retyc-machine-v1\n"
)

// JWK is the public signing key sent at enrollment. The backend accepts
// exactly these seven members, so none is optional.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
}

// GenerateSigningKey returns a fresh P-256 key.
func GenerateSigningKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// MarshalSigningKey encodes k as a PKCS#8 "PRIVATE KEY" PEM block.
func MarshalSigningKey(k *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, fmt.Errorf("encode signing key: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: der}), nil
}

// ParseSigningKey decodes a PKCS#8 PEM key, refusing anything but EC P-256.
// Errors never include key material.
func ParseSigningKey(pemData []byte) (*ecdsa.PrivateKey, error) {
	blk, _ := pem.Decode(pemData)
	if blk == nil || blk.Type != pemType {
		return nil, errors.New("signing key: no PKCS#8 PRIVATE KEY PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, errors.New("signing key: invalid PKCS#8 encoding")
	}
	k, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("signing key: not an EC key")
	}
	if k.Curve != elliptic.P256() {
		return nil, errors.New("signing key: curve is not P-256")
	}

	return k, nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// coords returns x and y as base64url, left-padded to 32 bytes.
func coords(k *ecdsa.PublicKey) (x, y string) {
	// Uncompressed point: 0x04 || X || Y, coordinates already 32 bytes
	pt, err := k.Bytes()
	if err != nil || len(pt) != 1+2*coordinateSize {
		return "", ""
	}

	return b64(pt[1 : 1+coordinateSize]), b64(pt[1+coordinateSize:])
}

// Thumbprint is the RFC 7638 SHA-256 thumbprint of k, base64url without padding.
func Thumbprint(k *ecdsa.PublicKey) string {
	x, y := coords(k)
	// Required members in lexicographic order, no whitespace
	canon := `{"crv":"P-256","kty":"EC","x":"` + x + `","y":"` + y + `"}`
	sum := sha256.Sum256([]byte(canon))

	return b64(sum[:])
}

// PublicJWK builds the enrollment JWK of k; kid is its thumbprint.
func PublicJWK(k *ecdsa.PublicKey) JWK {
	x, y := coords(k)

	return JWK{Kty: "EC", Crv: "P-256", X: x, Y: y, Kid: Thumbprint(k), Alg: "ES256", Use: "sig"}
}

// Fingerprint binds the signing key id to the AGE recipient; the admin
// compares it out of band. Format XXXX-XXXX-XXXX-XXXX.
func Fingerprint(kid, ageRecipient string) string {
	sum := sha256.Sum256([]byte(fingerprintTag + kid + "\n" + ageRecipient))
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:])[:16]

	return strings.Join([]string{enc[0:4], enc[4:8], enc[8:12], enc[12:16]}, "-")
}

// SignAssertion returns an ES256 client assertion (RFC 7523) valid 30 s.
func SignAssertion(k *ecdsa.PrivateKey, kid, clientID, audience string, now time.Time) (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", fmt.Errorf("assertion id: %w", err)
	}
	header, err := json.Marshal(map[string]string{"alg": "ES256", "kid": kid, "typ": "JWT"})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(map[string]any{
		"iss": clientID,
		"sub": clientID,
		"aud": audience,
		"iat": now.Unix(),
		"exp": now.Add(assertionTTL).Unix(),
		"jti": hex.EncodeToString(id[:]),
	})
	if err != nil {
		return "", err
	}
	signing := b64(header) + "." + b64(claims)
	digest := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, k, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign assertion: %w", err)
	}
	var sig [2 * coordinateSize]byte
	r.FillBytes(sig[:coordinateSize])
	s.FillBytes(sig[coordinateSize:])

	return signing + "." + b64(sig[:]), nil
}

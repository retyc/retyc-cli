// Package crypto provides helpers for encrypting and decrypting data using AGE.
// AGE (Actually Good Encryption) is a simple, modern file encryption tool.
// See https://age-encryption.org for the specification.
package crypto

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// GenerateKeyPair creates a new X25519 AGE key pair and returns the recipient
// (public key) and the identity (private key).
func GenerateKeyPair() (*age.X25519Identity, error) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, fmt.Errorf("generating AGE identity: %w", err)
	}
	return identity, nil
}

// ParseIdentity parses an AGE private key from its string representation
// (AGE-SECRET-KEY-1…).
func ParseIdentity(privateKey string) (*age.X25519Identity, error) {
	id, err := age.ParseX25519Identity(strings.TrimSpace(privateKey))
	if err != nil {
		return nil, fmt.Errorf("parsing AGE identity: %w", err)
	}
	return id, nil
}

// ParseRecipient parses an AGE public key (age1…).
func ParseRecipient(publicKey string) (*age.X25519Recipient, error) {
	rec, err := age.ParseX25519Recipient(strings.TrimSpace(publicKey))
	if err != nil {
		return nil, fmt.Errorf("parsing AGE recipient: %w", err)
	}
	return rec, nil
}

// Encrypt encrypts plaintext for the given recipients and returns an armored
// (PEM-like ASCII) ciphertext string.
func Encrypt(plaintext []byte, recipients ...age.Recipient) (string, error) {
	var buf bytes.Buffer
	armorWriter := armor.NewWriter(&buf)

	w, err := age.Encrypt(armorWriter, recipients...)
	if err != nil {
		return "", fmt.Errorf("creating AGE encryptor: %w", err)
	}

	if _, err := w.Write(plaintext); err != nil {
		return "", fmt.Errorf("encrypting data: %w", err)
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("finalizing encryption: %w", err)
	}
	if err := armorWriter.Close(); err != nil {
		return "", fmt.Errorf("finalizing armor: %w", err)
	}

	return buf.String(), nil
}

// Decrypt decrypts an armored AGE ciphertext using the provided identities.
func Decrypt(ciphertext string, identities ...age.Identity) ([]byte, error) {
	armorReader := armor.NewReader(strings.NewReader(ciphertext))

	r, err := age.Decrypt(armorReader, identities...)
	if err != nil {
		return nil, fmt.Errorf("creating AGE decryptor: %w", err)
	}

	plaintext, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("decrypting data: %w", err)
	}
	return plaintext, nil
}

// EncryptToString is a convenience wrapper that encrypts a string value.
func EncryptToString(value string, recipients ...age.Recipient) (string, error) {
	return Encrypt([]byte(value), recipients...)
}

// DecryptToString is a convenience wrapper that decrypts to a string value.
func DecryptToString(ciphertext string, identities ...age.Identity) (string, error) {
	b, err := Decrypt(ciphertext, identities...)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

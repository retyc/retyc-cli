// Package crypto provides helpers for encrypting and decrypting data using AGE.
// AGE (Actually Good Encryption) is a simple, modern file encryption tool.
// See https://age-encryption.org for the specification.
//
// All keys use the post-quantum hybrid MLKEM768-X25519 scheme:
//   - Private keys: AGE-SECRET-KEY-PQ-1… (HybridIdentity)
//   - Public keys:  age1pq1…              (HybridRecipient)
package crypto

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// GenerateKeyPair generates a new post-quantum hybrid MLKEM768-X25519 key pair.
func GenerateKeyPair() (*age.HybridIdentity, error) {
	identity, err := age.GenerateHybridIdentity()
	if err != nil {
		return nil, fmt.Errorf("generating AGE identity: %w", err)
	}
	return identity, nil
}

// ParseIdentity parses a post-quantum AGE private key (AGE-SECRET-KEY-PQ-1…).
func ParseIdentity(privateKey string) (*age.HybridIdentity, error) {
	id, err := age.ParseHybridIdentity(strings.TrimSpace(privateKey))
	if err != nil {
		return nil, fmt.Errorf("parsing AGE identity: %w", err)
	}
	return id, nil
}

// ParseRecipient parses a post-quantum AGE public key (age1pq1…).
func ParseRecipient(publicKey string) (*age.HybridRecipient, error) {
	rec, err := age.ParseHybridRecipient(strings.TrimSpace(publicKey))
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
		return nil, fmt.Errorf("decrypting: %w", err)
	}

	plaintext, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading decrypted data: %w", err)
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

// DecryptWithPassphrase decrypts an armored AGE ciphertext that was encrypted
// with a passphrase (scrypt recipient).
func DecryptWithPassphrase(ciphertext string, passphrase string) ([]byte, error) {
	identity, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return nil, fmt.Errorf("creating scrypt identity: %w", err)
	}
	return Decrypt(ciphertext, identity)
}

// DecryptToStringWithPassphrase is a convenience wrapper for passphrase-based decryption.
func DecryptToStringWithPassphrase(ciphertext string, passphrase string) (string, error) {
	b, err := DecryptWithPassphrase(ciphertext, passphrase)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// EncryptStringForKeys encrypts value as armored AGE for the given list of public keys.
func EncryptStringForKeys(value string, publicKeys []string) (string, error) {
	recipients := make([]age.Recipient, 0, len(publicKeys))
	for _, pk := range publicKeys {
		if pk == "" {
			continue
		}
		rec, err := ParseRecipient(pk)
		if err != nil {
			return "", fmt.Errorf("invalid public key %q: %w", pk, err)
		}
		recipients = append(recipients, rec)
	}
	if len(recipients) == 0 {
		return "", fmt.Errorf("no valid recipients")
	}
	return EncryptToString(value, recipients...)
}

// EncryptBinaryForKey encrypts plaintext as raw (non-armored) binary AGE using publicKey.
// Binary format (no armor) is required for file chunk uploads.
func EncryptBinaryForKey(plaintext []byte, publicKey string) ([]byte, error) {
	rec, err := ParseRecipient(publicKey)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, rec)
	if err != nil {
		return nil, fmt.Errorf("creating AGE encryptor: %w", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, fmt.Errorf("encrypting data: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("finalizing encryption: %w", err)
	}
	return buf.Bytes(), nil
}

// EncryptWithPassphrase encrypts plaintext as armored AGE with a scrypt (passphrase) recipient.
func EncryptWithPassphrase(plaintext []byte, passphrase string) (string, error) {
	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return "", fmt.Errorf("creating scrypt recipient: %w", err)
	}
	return Encrypt(plaintext, recipient)
}

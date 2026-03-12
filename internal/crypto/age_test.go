package crypto

import (
	"bytes"
	"strings"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	identity, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	rec := identity.Recipient().String()
	if !strings.HasPrefix(rec, "age1pq1") {
		t.Errorf("recipient %q does not start with age1pq1", rec)
	}
}

func TestGenerateKeyPair_Uniqueness(t *testing.T) {
	id1, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	id2, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	if id1.String() == id2.String() {
		t.Error("GenerateKeyPair() returned identical private keys")
	}
}

func TestParseIdentity_Valid(t *testing.T) {
	original, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := ParseIdentity(original.String())
	if err != nil {
		t.Fatalf("ParseIdentity() error = %v", err)
	}

	if parsed.String() != original.String() {
		t.Error("ParseIdentity() round-trip changed the private key")
	}
}

func TestParseIdentity_Whitespace(t *testing.T) {
	original, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	_, err = ParseIdentity("  " + original.String() + "\n")
	if err != nil {
		t.Errorf("ParseIdentity() should strip whitespace, got: %v", err)
	}
}

func TestParseIdentity_Invalid(t *testing.T) {
	_, err := ParseIdentity("not-a-valid-private-key")
	if err == nil {
		t.Error("ParseIdentity() should return error for invalid key")
	}
}

func TestParseRecipient_Valid(t *testing.T) {
	identity, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	pubKey := identity.Recipient().String()

	parsed, err := ParseRecipient(pubKey)
	if err != nil {
		t.Fatalf("ParseRecipient() error = %v", err)
	}

	if parsed.String() != pubKey {
		t.Error("ParseRecipient() round-trip changed the public key")
	}
}

func TestParseRecipient_Invalid(t *testing.T) {
	_, err := ParseRecipient("not-a-valid-public-key")
	if err == nil {
		t.Error("ParseRecipient() should return error for invalid key")
	}
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	identity, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("hello, world — retyc test payload")

	ciphertext, err := Encrypt(plaintext, identity.Recipient())
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	got, err := Decrypt(ciphertext, identity)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	if !bytes.Equal(got, plaintext) {
		t.Errorf("Decrypt() = %q, want %q", got, plaintext)
	}
}

func TestEncryptDecrypt_EmptyPlaintext(t *testing.T) {
	identity, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, err := Encrypt([]byte{}, identity.Recipient())
	if err != nil {
		t.Fatalf("Encrypt() empty plaintext error = %v", err)
	}

	got, err := Decrypt(ciphertext, identity)
	if err != nil {
		t.Fatalf("Decrypt() empty plaintext error = %v", err)
	}

	if len(got) != 0 {
		t.Errorf("Decrypt() = %q, want empty", got)
	}
}

func TestEncryptDecrypt_WrongKey(t *testing.T) {
	identity1, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	identity2, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, err := Encrypt([]byte("secret"), identity1.Recipient())
	if err != nil {
		t.Fatal(err)
	}

	_, err = Decrypt(ciphertext, identity2)
	if err == nil {
		t.Error("Decrypt() should fail when using the wrong key")
	}
}

func TestDecrypt_InvalidCiphertext(t *testing.T) {
	identity, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	_, err = Decrypt("this is not valid age ciphertext", identity)
	if err == nil {
		t.Error("Decrypt() should return error for invalid ciphertext")
	}
}

func TestEncryptToString_DecryptToString_RoundTrip(t *testing.T) {
	identity, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	original := "plaintext string value"

	ciphertext, err := EncryptToString(original, identity.Recipient())
	if err != nil {
		t.Fatalf("EncryptToString() error = %v", err)
	}

	got, err := DecryptToString(ciphertext, identity)
	if err != nil {
		t.Fatalf("DecryptToString() error = %v", err)
	}

	if got != original {
		t.Errorf("DecryptToString() = %q, want %q", got, original)
	}
}

func TestEncryptWithPassphrase_DecryptWithPassphrase_RoundTrip(t *testing.T) {
	passphrase := "correct-horse-battery-staple"
	plaintext := []byte("super secret data")

	ciphertext, err := EncryptWithPassphrase(plaintext, passphrase)
	if err != nil {
		t.Fatalf("EncryptWithPassphrase() error = %v", err)
	}

	got, err := DecryptWithPassphrase(ciphertext, passphrase)
	if err != nil {
		t.Fatalf("DecryptWithPassphrase() error = %v", err)
	}

	if !bytes.Equal(got, plaintext) {
		t.Errorf("DecryptWithPassphrase() = %q, want %q", got, plaintext)
	}
}

func TestDecryptWithPassphrase_WrongPassphrase(t *testing.T) {
	ciphertext, err := EncryptWithPassphrase([]byte("secret"), "correct-pass")
	if err != nil {
		t.Fatal(err)
	}

	_, err = DecryptWithPassphrase(ciphertext, "wrong-pass")
	if err == nil {
		t.Error("DecryptWithPassphrase() should fail with wrong passphrase")
	}
}

func TestDecryptToStringWithPassphrase_RoundTrip(t *testing.T) {
	passphrase := "test-passphrase-123"
	original := "value to encrypt and decrypt"

	ciphertext, err := EncryptWithPassphrase([]byte(original), passphrase)
	if err != nil {
		t.Fatalf("EncryptWithPassphrase() error = %v", err)
	}

	got, err := DecryptToStringWithPassphrase(ciphertext, passphrase)
	if err != nil {
		t.Fatalf("DecryptToStringWithPassphrase() error = %v", err)
	}

	if got != original {
		t.Errorf("DecryptToStringWithPassphrase() = %q, want %q", got, original)
	}
}

func TestEncryptBinaryForKey_DecryptBinary_RoundTrip(t *testing.T) {
	identity, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte{0x00, 0xff, 0xab, 0xcd, 0xef, 0x42, 0x00}

	encrypted, err := EncryptBinaryForKey(plaintext, identity.Recipient().String())
	if err != nil {
		t.Fatalf("EncryptBinaryForKey() error = %v", err)
	}

	got, err := DecryptBinary(encrypted, identity)
	if err != nil {
		t.Fatalf("DecryptBinary() error = %v", err)
	}

	if !bytes.Equal(got, plaintext) {
		t.Errorf("DecryptBinary() = %v, want %v", got, plaintext)
	}
}

func TestEncryptBinaryForKey_WrongKey(t *testing.T) {
	identity1, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	identity2, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	encrypted, err := EncryptBinaryForKey([]byte("data"), identity1.Recipient().String())
	if err != nil {
		t.Fatal(err)
	}

	_, err = DecryptBinary(encrypted, identity2)
	if err == nil {
		t.Error("DecryptBinary() should fail with wrong key")
	}
}

func TestEncryptBinaryForKey_InvalidKey(t *testing.T) {
	_, err := EncryptBinaryForKey([]byte("data"), "not-a-valid-public-key")
	if err == nil {
		t.Error("EncryptBinaryForKey() should return error for invalid key")
	}
}

func TestDecryptBinary_InvalidData(t *testing.T) {
	identity, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	_, err = DecryptBinary([]byte("not valid binary age data"), identity)
	if err == nil {
		t.Error("DecryptBinary() should return error for invalid data")
	}
}

func TestEncryptStringForKeys_SingleKey(t *testing.T) {
	identity, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	original := "test value"

	ciphertext, err := EncryptStringForKeys(original, []string{identity.Recipient().String()})
	if err != nil {
		t.Fatalf("EncryptStringForKeys() error = %v", err)
	}

	got, err := DecryptToString(ciphertext, identity)
	if err != nil {
		t.Fatalf("DecryptToString() error = %v", err)
	}

	if got != original {
		t.Errorf("got %q, want %q", got, original)
	}
}

func TestEncryptStringForKeys_MultipleKeys(t *testing.T) {
	identity1, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	identity2, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	original := "multi-recipient secret"

	ciphertext, err := EncryptStringForKeys(original, []string{
		identity1.Recipient().String(),
		identity2.Recipient().String(),
	})
	if err != nil {
		t.Fatalf("EncryptStringForKeys() error = %v", err)
	}

	// Both recipients must be able to decrypt independently.
	got1, err := DecryptToString(ciphertext, identity1)
	if err != nil {
		t.Fatalf("identity1 DecryptToString() error = %v", err)
	}

	got2, err := DecryptToString(ciphertext, identity2)
	if err != nil {
		t.Fatalf("identity2 DecryptToString() error = %v", err)
	}

	if got1 != original || got2 != original {
		t.Errorf("got1=%q got2=%q, want %q", got1, got2, original)
	}
}

func TestEncryptStringForKeys_SkipsEmptyKeys(t *testing.T) {
	identity, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Empty strings mixed with a valid key should be silently skipped.
	ciphertext, err := EncryptStringForKeys("hello", []string{
		"",
		identity.Recipient().String(),
		"",
	})
	if err != nil {
		t.Fatalf("EncryptStringForKeys() error = %v", err)
	}

	got, err := DecryptToString(ciphertext, identity)
	if err != nil || got != "hello" {
		t.Errorf("DecryptToString() = %q, err = %v", got, err)
	}
}

func TestEncryptStringForKeys_NoValidKeys(t *testing.T) {
	_, err := EncryptStringForKeys("hello", []string{"", ""})
	if err == nil {
		t.Error("EncryptStringForKeys() should return error with no valid recipients")
	}

	if !strings.Contains(err.Error(), "no valid recipients") {
		t.Errorf("error %q should mention 'no valid recipients'", err.Error())
	}
}

func TestEncryptStringForKeys_InvalidKey(t *testing.T) {
	_, err := EncryptStringForKeys("hello", []string{"not-a-valid-key"})
	if err == nil {
		t.Error("EncryptStringForKeys() should return error for invalid key")
	}
}

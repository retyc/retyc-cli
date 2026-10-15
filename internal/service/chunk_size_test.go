package service

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/crypto"
)

// The size of an encrypted chunk, and the plaintext size read back from it,
// against what the encryption really makes: an empty chunk, the edges of an
// AGE segment, a whole chunk of this CLI.
func TestChunkSizeArithmeticMatchesTheEncryption(t *testing.T) {
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	sess := &DataroomSession{Identity: identity}
	envelope, err := sess.chunkEnvelope()
	if err != nil {
		t.Fatalf("chunkEnvelope: %v", err)
	}
	// The same key always makes the same envelope: that is what lets one
	// measure stand for every chunk.
	if again, _ := (&DataroomSession{PublicKey: identity.Recipient().String()}).chunkEnvelope(); again != envelope {
		t.Errorf("envelope measured from the public key = %d, from the identity %d", again, envelope)
	}

	for _, plain := range []int{
		0, 1, 15, 16, 17, 65535, 65536, 65537, 2*65536 - 1, 2 * 65536, 2*65536 + 1, 1 << 20, 6618134,
		UploadChunkSize - 1, UploadChunkSize, UploadChunkSize + 1,
	} {
		enc, err := crypto.EncryptBinaryForKey(make([]byte, plain), identity.Recipient().String())
		if err != nil {
			t.Fatalf("encrypting %d bytes: %v", plain, err)
		}
		if got := encryptedChunkSize(int64(plain), envelope); got != int64(len(enc)) {
			t.Errorf("encryptedChunkSize(%d) = %d, the encryption makes %d", plain, got, len(enc))
		}
		if got, ok := plainChunkSize(int64(len(enc)), envelope); !ok || got != int64(plain) {
			t.Errorf("plainChunkSize(%d) = %d, %v; want %d", len(enc), got, ok, plain)
		}
	}

	// The sizes measured on the API, under the header it was measured with:
	// 8 MiB, 16 MiB and a last chunk.
	const measuredEnvelope = 1627 + ageStreamNonce
	for encrypted, plain := range map[int64]int64{8392299: 8 << 20, 16782955: 16 << 20, 6621393: 6618134} {
		if got, ok := plainChunkSize(encrypted, measuredEnvelope); !ok || got != plain {
			t.Errorf("plainChunkSize(%d) = %d, %v; want %d", encrypted, got, ok, plain)
		}
	}

	// Sizes no plaintext encrypts to: shorter than the envelope and a tag,
	// or a segment holding its tag alone after a full one.
	for _, encrypted := range []int64{
		0, envelope, envelope + ageStreamTag - 1, envelope + ageStreamSegment + 2*ageStreamTag,
	} {
		if got, ok := plainChunkSize(encrypted, envelope); ok {
			t.Errorf("plainChunkSize(%d) = %d, want no plaintext size", encrypted, got)
		}
	}
}

// DataroomChunkPlainSize asks for the size of the chunk as stored, one HEAD,
// and returns what it holds once decrypted.
func TestDataroomChunkPlainSize(t *testing.T) {
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	enc, err := crypto.EncryptBinaryForKey(make([]byte, 70000), identity.Recipient().String())
	if err != nil {
		t.Fatal(err)
	}
	var (
		requests []string
		length   = len(enc)
		status   = http.StatusOK
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Length", strconv.Itoa(length))
		w.WriteHeader(status)
	}))
	defer srv.Close()
	client := newKeyTestClient(srv)
	sess := &DataroomSession{Identity: identity}

	got, err := DataroomChunkPlainSize(context.Background(), client, "v1", 0, sess)
	if err != nil || got != 70000 {
		t.Fatalf("DataroomChunkPlainSize = %d, %v; want 70000", got, err)
	}
	if len(requests) != 1 || requests[0] != "HEAD /dataroom/node/version/v1/chunk/0" {
		t.Errorf("requests = %v, want one HEAD of the chunk route", requests)
	}

	// A length no chunk of this dataroom has is no answer.
	length = 12
	if _, err := DataroomChunkPlainSize(context.Background(), client, "v1", 0, sess); !errors.Is(err, api.ErrNoChunkSize) {
		t.Errorf("error = %v, want api.ErrNoChunkSize", err)
	}
	// The refusals of the API pass through.
	length, status = 0, http.StatusNotFound
	_, err = DataroomChunkPlainSize(context.Background(), client, "v1", 0, sess)
	if !errors.Is(err, api.ErrNotFound) || errors.Is(err, api.ErrNoChunkSize) {
		t.Errorf("error = %v, want api.ErrNotFound alone", err)
	}
	status = http.StatusMethodNotAllowed
	if _, err := DataroomChunkPlainSize(context.Background(), client, "v1", 0, sess); !errors.Is(err, api.ErrNoChunkSize) {
		t.Errorf("error = %v, want api.ErrNoChunkSize", err)
	}
}

// ReadDataroomChunkBounded reads a chunk of the limit and refuses one byte
// more, undecrypted.
func TestReadDataroomChunkBounded(t *testing.T) {
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	const limit = 65536 // the edge of an AGE segment
	sizes := map[string]int{"/dataroom/node/version/v1/chunk/0": limit, "/dataroom/node/version/v1/chunk/1": limit + 1}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		enc, err := crypto.EncryptBinaryForKey(make([]byte, sizes[r.URL.Path]), identity.Recipient().String())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)

			return
		}
		_, _ = w.Write(enc)
	}))
	defer srv.Close()
	client := newKeyTestClient(srv)
	sess := &DataroomSession{Identity: identity}

	before := cryptoSamples(t, "decrypt")
	got, err := ReadDataroomChunkBounded(context.Background(), client, "v1", 0, sess, limit)
	if err != nil || len(got) != limit {
		t.Fatalf("chunk of the limit: %d bytes, %v", len(got), err)
	}
	_, err = ReadDataroomChunkBounded(context.Background(), client, "v1", 1, sess, limit)
	if !errors.Is(err, api.ErrChunkTooLarge) {
		t.Fatalf("chunk over the limit: error = %v, want api.ErrChunkTooLarge", err)
	}
	if n := cryptoSamples(t, "decrypt") - before; n != 1 {
		t.Errorf("%d chunks decrypted, want 1: the oversized one is refused before", n)
	}
}

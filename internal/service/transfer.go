package service

import (
	"context"
	cryptorand "crypto/rand"
	"fmt"
	"math/big"
	"mime"
	"os"
	"path/filepath"
	"time"

	"filippo.io/age"
	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/config"
	"github.com/retyc/retyc-cli/internal/crypto"
)

// ListTransfers returns a page of the authenticated user's transfers.
// filter must be "sent" or "received".
func ListTransfers(ctx context.Context, client *api.Client, filter string, page int) (*ListTransfersResult, error) {
	result, err := client.ListTransfers(ctx, filter, page)
	if err != nil {
		return nil, fmt.Errorf("listing transfers: %w", err)
	}

	return &ListTransfersResult{
		Items: result.Items,
		Total: result.Total,
		Pages: result.Pages,
		Page:  result.Page,
	}, nil
}

// GetTransferInfo fetches and decrypts the full details of a transfer.
// reader is used to obtain the user's AGE key passphrase when not cached.
func GetTransferInfo(
	ctx context.Context, cfg *config.Config, client *api.Client, shareID string, reader PassphraseReader,
) (*TransferInfoResult, error) {
	type detailsRes struct {
		v   *api.TransferDetails
		err error
	}
	type keyRes struct {
		v   *api.UserKey
		err error
	}

	detailsCh := make(chan detailsRes, 1)
	keyCh := make(chan keyRes, 1)
	go func() { v, err := client.GetTransferDetails(ctx, shareID); detailsCh <- detailsRes{v, err} }()
	go func() { v, err := client.GetActiveKey(ctx); keyCh <- keyRes{v, err} }()

	dr := <-detailsCh
	kr := <-keyCh

	if dr.err != nil {
		return nil, fmt.Errorf("fetching transfer: %w", dr.err)
	}
	if kr.err != nil {
		return nil, fmt.Errorf("fetching encryption key: %w", kr.err)
	}

	result := &TransferInfoResult{Details: dr.v}

	if dr.v.SessionPrivateKeyEnc == nil || kr.v == nil {
		return result, nil
	}

	userIdentity, err := ResolveUserIdentity(cfg, kr.v, reader)
	if err != nil {
		return nil, err
	}

	sessionKeyStr, err := crypto.DecryptToString(*dr.v.SessionPrivateKeyEnc, userIdentity)
	if err != nil {
		return nil, fmt.Errorf("decrypting session key (key mismatch?): %w", err)
	}

	sessionIdentity, err := crypto.ParseIdentity(sessionKeyStr)
	if err != nil {
		return nil, fmt.Errorf("parsing session identity: %w", err)
	}

	if dr.v.MessageEnc != nil {
		msg, decErr := crypto.DecryptToString(*dr.v.MessageEnc, sessionIdentity)
		if decErr == nil {
			result.Message = msg
		}
	}

	filePage, err := client.ListFiles(ctx, shareID, 1)
	if err != nil {
		return nil, fmt.Errorf("fetching files: %w", err)
	}

	for _, f := range filePage.Items {
		name, decErr := crypto.DecryptToString(f.NameEnc, sessionIdentity)
		if decErr != nil {
			name = "(encrypted)"
		}
		mimeType := ""
		if f.TypeEnc != "" {
			mimeType, _ = crypto.DecryptToString(f.TypeEnc, sessionIdentity)
		}
		result.Files = append(result.Files, TransferFileInfo{
			ID:         f.ID,
			Name:       name,
			MIMEType:   mimeType,
			Size:       f.OriginalSize,
			ChunkCount: f.ChunkCount,
		})
	}

	return result, nil
}

// SendTransfer creates and uploads a new transfer.
// The passphrase (when needed) must be set in p.Passphrase or p.GeneratePassphrase
// must be true; no interactive prompt is performed.
// reader is used to obtain the user's AGE key passphrase.
func SendTransfer(
	ctx context.Context, cfg *config.Config, client *api.Client,
	p SendTransferParams, reader PassphraseReader, progress ProgressFn,
) (result *SendTransferResult, err error) {
	userKey, err := client.GetActiveKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching encryption key: %w", err)
	}
	if userKey == nil {
		return nil, fmt.Errorf("no active encryption key - set up your key in the web interface first")
	}

	passphrase := p.Passphrase
	if p.GeneratePassphrase {
		passphrase, err = GenerateTransferPassphrase()
		if err != nil {
			return nil, fmt.Errorf("generating passphrase: %w", err)
		}
	}

	var titlePtr *string
	if p.Title != "" {
		titlePtr = &p.Title
	}

	share, err := client.CreateShare(ctx, p.ExpireSecs, titlePtr, true, p.ToEmails)
	if err != nil {
		return nil, fmt.Errorf("creating transfer: %w", err)
	}

	// Best-effort cleanup if anything fails after share creation.
	var shareID = share.ID
	defer func() {
		if err != nil {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if delErr := client.ForceDeleteTransfer(cleanupCtx, shareID); delErr != nil {
				fmt.Fprintf(os.Stderr,
					"warning: could not clean up pending transfer %s: %v\n", shareID, delErr)
			}
		}
	}()

	allHaveKeys := len(p.ToEmails) > 0 && len(share.PublicKeys) == len(p.ToEmails)
	needPassphrase := !allHaveKeys || p.Passphrase != "" || p.GeneratePassphrase

	if needPassphrase && passphrase == "" {
		err = fmt.Errorf("transfer passphrase required but not provided (use --passphrase or --generate-passphrase)")

		return nil, err
	}

	sessionIdentity, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generating session key: %w", err)
	}
	sessionPrivKey := sessionIdentity.String()
	sessionPubKey := sessionIdentity.Recipient().String()

	allPubKeys := append([]string{userKey.PublicKey}, share.PublicKeys...)
	sessionPrivKeyEnc, err := crypto.EncryptStringForKeys(sessionPrivKey, allPubKeys)
	if err != nil {
		return nil, fmt.Errorf("encrypting session key: %w", err)
	}

	var ephemeralPrivKeyEnc, ephemeralPubKey, sessionPrivKeyEncForPassphrase string
	if needPassphrase {
		ephemeralIdentity, genErr := crypto.GenerateKeyPair()
		if genErr != nil {
			return nil, fmt.Errorf("generating ephemeral key: %w", genErr)
		}
		ephPubKey := ephemeralIdentity.Recipient().String()
		ephPrivKey := ephemeralIdentity.String()

		enc, encErr := crypto.EncryptWithPassphrase([]byte(ephPrivKey), passphrase)
		if encErr != nil {
			return nil, fmt.Errorf("encrypting ephemeral key: %w", encErr)
		}
		sesEnc, encErr := crypto.EncryptStringForKeys(sessionPrivKey, []string{ephPubKey})
		if encErr != nil {
			return nil, fmt.Errorf("encrypting session key for passphrase: %w", encErr)
		}
		ephemeralPrivKeyEnc = enc
		ephemeralPubKey = ephPubKey
		sessionPrivKeyEncForPassphrase = sesEnc
	}

	for _, filePath := range p.FilePaths {
		if uploadErr := uploadTransferFile(ctx, client, share.ID, filePath, sessionPubKey, progress); uploadErr != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Base(filePath), uploadErr)
		}
	}

	var messageEnc *string
	if p.Message != "" {
		enc, encErr := crypto.EncryptStringForKeys(p.Message, []string{sessionPubKey})
		if encErr != nil {
			return nil, fmt.Errorf("encrypting message: %w", encErr)
		}
		messageEnc = &enc
	}

	req := api.CompleteTransferRequest{
		SessionPrivateKeyEnc: sessionPrivKeyEnc,
		SessionPublicKey:     sessionPubKey,
		MessageEnc:           messageEnc,
	}
	if needPassphrase {
		req.EphemeralPrivateKeyEnc = &ephemeralPrivKeyEnc
		req.EphemeralPublicKey = &ephemeralPubKey
		req.SessionPrivateKeyEncForPassphrase = &sessionPrivKeyEncForPassphrase
	}
	if err = client.CompleteTransfer(ctx, share.ID, req); err != nil {
		return nil, fmt.Errorf("completing transfer: %w", err)
	}

	out := &SendTransferResult{
		ID:         share.ID,
		Passphrase: passphrase,
	}
	if details, detErr := client.GetTransferDetails(ctx, share.ID); detErr == nil {
		out.WebURL = details.WebURL
	}

	return out, nil
}

// DownloadTransfer downloads and decrypts all files from a transfer into outputDir.
// reader is used to obtain the user's AGE key passphrase when not cached.
// Set p.Passphrase when the user has no key for this transfer (passphrase path).
func DownloadTransfer(
	ctx context.Context, cfg *config.Config, client *api.Client,
	p DownloadTransferParams, reader PassphraseReader, progress ProgressFn,
) (*DownloadTransferResult, error) {
	type detailsRes struct {
		v   *api.TransferDetails
		err error
	}
	type keyRes struct {
		v   *api.UserKey
		err error
	}

	detailsCh := make(chan detailsRes, 1)
	keyCh := make(chan keyRes, 1)
	go func() { v, err := client.GetTransferDetails(ctx, p.ShareID); detailsCh <- detailsRes{v, err} }()
	go func() { v, err := client.GetActiveKey(ctx); keyCh <- keyRes{v, err} }()

	dr := <-detailsCh
	kr := <-keyCh

	if dr.err != nil {
		return nil, fmt.Errorf("fetching transfer: %w", dr.err)
	}
	if kr.err != nil {
		return nil, fmt.Errorf("fetching encryption key: %w", kr.err)
	}

	details := dr.v

	if details.SessionPrivateKeyEnc == nil && details.SessionPrivateKeyEncForPassphrase == nil {
		return nil, fmt.Errorf("transfer not yet completed - no encrypted content available")
	}

	var sessionIdentity *age.HybridIdentity

	if kr.v != nil && details.SessionPrivateKeyEnc != nil {
		userIdentity, err := ResolveUserIdentity(cfg, kr.v, reader)
		if err != nil {
			return nil, err
		}
		sessionPrivKey, err := crypto.DecryptToString(*details.SessionPrivateKeyEnc, userIdentity)
		if err != nil {
			return nil, fmt.Errorf("decrypting session key (key mismatch?): %w", err)
		}
		si, err := crypto.ParseIdentity(sessionPrivKey)
		if err != nil {
			return nil, fmt.Errorf("parsing session identity: %w", err)
		}
		sessionIdentity = si
	} else {
		if details.EphemeralPrivateKeyEnc == nil || details.SessionPrivateKeyEncForPassphrase == nil {
			return nil, fmt.Errorf("no decryption path available - neither user key nor passphrase data found")
		}
		if p.Passphrase == "" {
			return nil, fmt.Errorf("transfer passphrase required but not provided")
		}
		ephPrivKey, err := crypto.DecryptToStringWithPassphrase(*details.EphemeralPrivateKeyEnc, p.Passphrase)
		if err != nil {
			return nil, fmt.Errorf("wrong transfer passphrase")
		}
		ephIdentity, err := crypto.ParseIdentity(ephPrivKey)
		if err != nil {
			return nil, fmt.Errorf("parsing ephemeral identity: %w", err)
		}
		sessionPrivKey, err := crypto.DecryptToString(*details.SessionPrivateKeyEncForPassphrase, ephIdentity)
		if err != nil {
			return nil, fmt.Errorf("decrypting session key: %w", err)
		}
		si, err := crypto.ParseIdentity(sessionPrivKey)
		if err != nil {
			return nil, fmt.Errorf("parsing session identity: %w", err)
		}
		sessionIdentity = si
	}

	var allFiles []api.TransferFile
	for page := 1; ; page++ {
		pg, err := client.ListFiles(ctx, p.ShareID, page)
		if err != nil {
			return nil, fmt.Errorf("listing files: %w", err)
		}
		allFiles = append(allFiles, pg.Items...)
		if page >= pg.Pages {
			break
		}
	}
	if len(allFiles) == 0 {
		return nil, fmt.Errorf("no files in this transfer")
	}

	type decryptedFile struct {
		api.TransferFile
		name string
	}
	decFiles := make([]decryptedFile, 0, len(allFiles))
	for _, f := range allFiles {
		name, err := crypto.DecryptToString(f.NameEnc, sessionIdentity)
		if err != nil {
			name = f.ID
		}
		decFiles = append(decFiles, decryptedFile{f, name})
	}

	outputDir := p.OutputDir
	if outputDir == "" {
		outputDir = "transfer-" + RandomLetters(8)
	}

	if _, err := os.Stat(outputDir); err == nil {
		for _, f := range decFiles {
			dest := filepath.Join(outputDir, f.name)
			if _, err := os.Stat(dest); err == nil {
				return nil, fmt.Errorf("file already exists: %s", dest)
			}
		}
	}
	if err := os.MkdirAll(outputDir, 0700); err != nil {
		return nil, fmt.Errorf("creating output directory: %w", err)
	}

	var downloadedFiles []string
	for _, f := range decFiles {
		if err := DownloadChunks(ctx, outputDir, f.name, f.OriginalSize, f.ChunkCount, sessionIdentity, progress,
			func(ctx context.Context, chunkID int) ([]byte, error) {
				return client.DownloadChunk(ctx, f.ID, chunkID)
			}); err != nil {
			return nil, fmt.Errorf("%s: %w", f.name, err)
		}
		downloadedFiles = append(downloadedFiles, f.name)
	}

	return &DownloadTransferResult{
		OutputDir: outputDir,
		Files:     downloadedFiles,
	}, nil
}

// DisableTransfer soft-deletes a transfer by its ID.
func DisableTransfer(ctx context.Context, client *api.Client, shareID string) error {
	if err := client.DisableTransfer(ctx, shareID); err != nil {
		return fmt.Errorf("disabling transfer: %w", err)
	}

	return nil
}

// EnableTransfer re-enables a previously disabled transfer.
func EnableTransfer(ctx context.Context, client *api.Client, shareID string) error {
	if err := client.EnableTransfer(ctx, shareID); err != nil {
		return fmt.Errorf("enabling transfer: %w", err)
	}

	return nil
}

// uploadTransferFile encrypts and uploads a single file in chunks to shareID.
func uploadTransferFile(
	ctx context.Context, client *api.Client, shareID, filePath, sessionPubKey string, progress ProgressFn,
) error {
	f, err := os.Open(filePath) //nolint:gosec // G304: path comes from validated user argument
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck

	info, err := f.Stat()
	if err != nil {
		return err
	}

	name := filepath.Base(filePath)
	mimeType := mime.TypeByExtension(filepath.Ext(filePath))
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}

	nameEnc, err := crypto.EncryptStringForKeys(name, []string{sessionPubKey})
	if err != nil {
		return fmt.Errorf("encrypting filename: %w", err)
	}
	typeEnc, err := crypto.EncryptStringForKeys(mimeType, []string{sessionPubKey})
	if err != nil {
		return fmt.Errorf("encrypting MIME type: %w", err)
	}

	fileModel, err := client.CreateFile(ctx, shareID, nameEnc, typeEnc, info.Size())
	if err != nil {
		return fmt.Errorf("registering file: %w", err)
	}

	return UploadChunks(ctx, f, info.Size(), name, sessionPubKey, progress,
		func(ctx context.Context, chunkID int, data []byte) error {
			return client.UploadChunk(ctx, fileModel.ID, chunkID, data)
		})
}

// GenerateTransferPassphrase generates a cryptographically secure 32-character passphrase
// drawn uniformly from the 94 printable non-space ASCII characters (0x21–0x7E).
func GenerateTransferPassphrase() (string, error) {
	const chars = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
	maxChar := big.NewInt(int64(len(chars)))
	result := make([]byte, 32)

	for i := range result {
		n, err := cryptorand.Int(cryptorand.Reader, maxChar)
		if err != nil {
			return "", err
		}
		result[i] = chars[n.Int64()]
	}

	return string(result), nil
}

// RandomLetters returns a string of n random lowercase ASCII letters.
// Uses crypto/rand.Int to avoid modular bias.
func RandomLetters(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	max := big.NewInt(int64(len(letters)))
	b := make([]byte, n)

	for i := range b {
		idx, err := cryptorand.Int(cryptorand.Reader, max)
		if err != nil {
			b[i] = 'a' // unreachable in practice

			continue
		}
		b[i] = letters[idx.Int64()]
	}

	return string(b)
}

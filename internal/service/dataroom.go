package service

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/config"
	"github.com/retyc/retyc-cli/internal/crypto"
)

// — URI and path helpers —————————————————————————————————————————————————————

// RetycURI holds the parsed components of a retyc://dataroom_id/path URI.
type RetycURI struct {
	DataroomID string
	Path       string // always starts with /
}

// IsRoot reports whether the URI refers to the dataroom root (path == "/").
func (r *RetycURI) IsRoot() bool { return r.Path == "/" }

// ParseRetycURI parses a URI of the form retyc://dataroom_id[/path].
func ParseRetycURI(s string) (*RetycURI, error) {
	const prefix = "retyc://"
	if !strings.HasPrefix(s, prefix) {
		return nil, fmt.Errorf("%q is not a retyc URI (expected retyc://dataroom-id/path)", s)
	}
	rest := strings.TrimPrefix(s, prefix)
	if rest == "" {
		return nil, fmt.Errorf("missing dataroom ID in %q", s)
	}
	idx := strings.IndexByte(rest, '/')
	var drID, nodePath string
	if idx < 0 {
		drID = rest
		nodePath = "/"
	} else {
		drID = rest[:idx]
		nodePath = rest[idx:]
	}
	if drID == "" {
		return nil, fmt.Errorf("missing dataroom ID in %q", s)
	}

	return &RetycURI{DataroomID: drID, Path: nodePath}, nil
}

// hasGlob reports whether s contains any glob metacharacter.
func hasGlob(s string) bool {
	return strings.ContainsAny(s, "*?[")
}

// splitPathParent splits a path into its parent and final component.
// e.g. "/Documents/report.pdf" → ("/Documents", "report.pdf").
func splitPathParent(p string) (parentPath, name string) {
	p = strings.TrimRight(p, "/")
	idx := strings.LastIndex(p, "/")
	if idx <= 0 {
		return "/", strings.TrimPrefix(p, "/")
	}

	return p[:idx], p[idx+1:]
}

// nodeNameHash computes SHA-256(salt + name) for deduplication.
func nodeNameHash(name, salt string) string {
	h := sha256.Sum256([]byte(salt + name))

	return hex.EncodeToString(h[:])
}

// isConflict reports whether err is an API 409 Conflict response.
func isConflict(err error) bool {
	return errors.Is(err, api.ErrConflict)
}

// — Dataroom session —————————————————————————————————————————————————————————

// dataroomSession holds the decrypted session material for a dataroom.
type dataroomSession struct {
	Identity   *age.HybridIdentity
	PublicKey  string
	PrivateKey string
	NameSalt   string
}

// resolveDataroomSession returns the session for dataroomID, through the
// process-wide SessionCache when EnableSessionCache was called, and by
// resolving it directly otherwise.
func resolveDataroomSession(
	ctx context.Context, cfg *config.Config, client *api.Client, dataroomID string, reader PassphraseReader,
) (*dataroomSession, error) {
	if c := processSessions.Load(); c != nil {
		return c.Get(ctx, dataroomID, func(ctx context.Context, drID string) (*DataroomSession, error) {
			return resolveDataroomSessionUncached(ctx, cfg, client, drID, reader)
		})
	}

	return resolveDataroomSessionUncached(ctx, cfg, client, dataroomID, reader)
}

// resolveDataroomSessionUncached fetches the dataroom and the user's active key
// concurrently, then decrypts the session key and per-dataroom name salt.
func resolveDataroomSessionUncached(
	ctx context.Context, cfg *config.Config, client *api.Client, dataroomID string, reader PassphraseReader,
) (*dataroomSession, error) {
	type drResult struct {
		v   *api.Dataroom
		err error
	}
	type keyResult struct {
		v   *api.UserKey
		err error
	}

	drCh := make(chan drResult, 1)
	keyCh := make(chan keyResult, 1)

	go func() { v, err := client.GetDataroom(ctx, dataroomID); drCh <- drResult{v, err} }()
	go func() { v, err := client.GetActiveKey(ctx); keyCh <- keyResult{v, err} }()

	dr := <-drCh
	kr := <-keyCh

	if dr.err != nil {
		return nil, fmt.Errorf("fetching dataroom: %w", dr.err)
	}
	if kr.err != nil {
		return nil, fmt.Errorf("fetching encryption key: %w", kr.err)
	}
	if kr.v == nil {
		return nil, fmt.Errorf("no active encryption key - set up your key in the web interface first")
	}

	userIdentity, err := ResolveUserIdentity(cfg, kr.v, reader)
	if err != nil {
		return nil, err
	}

	sessionPrivKey, err := crypto.DecryptToString(dr.v.SessionPrivateKeyEnc, userIdentity)
	if err != nil {
		return nil, fmt.Errorf("decrypting dataroom session key: %w", err)
	}

	sessionIdentity, err := crypto.ParseIdentity(sessionPrivKey)
	if err != nil {
		return nil, fmt.Errorf("parsing session AGE identity: %w", err)
	}

	var nameSalt string
	if dr.v.NodeNameSaltEnc != nil {
		nameSalt, err = crypto.DecryptToString(*dr.v.NodeNameSaltEnc, sessionIdentity)
		if err != nil {
			return nil, fmt.Errorf("decrypting name salt: %w", err)
		}
	}

	return &dataroomSession{
		Identity:   sessionIdentity,
		PublicKey:  dr.v.SessionPublicKey,
		PrivateKey: sessionPrivKey,
		NameSalt:   nameSalt,
	}, nil
}

// DataroomSession is the exported alias for the per-dataroom crypto session.
// Callers should cache it (see SessionCache): resolving it requires two API
// calls and AGE crypto.
type DataroomSession = dataroomSession

// GetDataroomSession resolves and returns the cryptographic session for a dataroom.
func GetDataroomSession(
	ctx context.Context, cfg *config.Config, client *api.Client, dataroomID string, reader PassphraseReader,
) (*DataroomSession, error) {
	return resolveDataroomSession(ctx, cfg, client, dataroomID, reader)
}

// fetchNodeItems lists the raw API node items at nodePath, supporting glob patterns.
// It is the shared fetch path behind ListNodes and ListNodesWithSession.
func fetchNodeItems(
	ctx context.Context, client *api.Client, dataroomID, nodePath string, identity *age.HybridIdentity,
) ([]api.DataroomNodeItem, error) {
	if hasGlob(nodePath) {
		return resolveGlob(ctx, client, dataroomID, nodePath, identity)
	}

	parentID, err := resolvePath(ctx, client, dataroomID, nodePath, identity)
	if err != nil {
		return nil, err
	}

	var items []api.DataroomNodeItem
	for page := 1; ; page++ {
		pg, err := client.ListDataroomNodes(ctx, dataroomID, parentID, page, 50)
		if err != nil {
			return nil, err
		}
		items = append(items, pg.Items...)
		if page >= pg.Pages {
			break
		}
	}

	return items, nil
}

// nodesFromItems decrypts API node items into DataroomNodeInfo using identity.
func nodesFromItems(items []api.DataroomNodeItem, identity *age.HybridIdentity) []DataroomNodeInfo {
	result := make([]DataroomNodeInfo, 0, len(items))
	for _, item := range items {
		name, decErr := crypto.DecryptToString(item.Node.NameEnc, identity)
		if decErr != nil {
			name = "(encrypted)"
		}
		nodeType := "dir"
		var size int64
		var versionID string
		var chunkCount int
		var mimeType string
		var modTime time.Time
		if item.Node.TypeEnc != nil {
			nodeType = "file"
			mimeType, _ = crypto.DecryptToString(*item.Node.TypeEnc, identity)
			if item.Version != nil {
				size = item.Version.OriginalSize
				versionID = item.Version.ID
				chunkCount = item.Version.ChunkCount
				modTime = item.Version.CreatedAt
			}
		}
		result = append(result, DataroomNodeInfo{
			ID:         item.Node.ID,
			Name:       name,
			Type:       nodeType,
			MIMEType:   mimeType,
			Size:       size,
			VersionID:  versionID,
			ChunkCount: chunkCount,
			modTime:    modTime,
		})
	}

	return result
}

// ListNodesWithSession lists all nodes at the given path using a pre-resolved session,
// avoiding the redundant resolveDataroomSession call in ListNodes.
func ListNodesWithSession(
	ctx context.Context, client *api.Client, dataroomID, nodePath string, sess *DataroomSession,
) ([]DataroomNodeInfo, error) {
	items, err := fetchNodeItems(ctx, client, dataroomID, nodePath, sess.Identity)
	if err != nil {
		return nil, err
	}

	return nodesFromItems(items, sess.Identity), nil
}

// — Node traversal helpers ————————————————————————————————————————————————————

// namedNode pairs a decrypted name with its API item.
type namedNode struct {
	name string
	item api.DataroomNodeItem
}

// fetchNodesWithNames lists all paginated nodes in a folder and decrypts their names.
func fetchNodesWithNames(
	ctx context.Context, client *api.Client, dataroomID string, parentID *string, identity *age.HybridIdentity,
) ([]namedNode, error) {
	var result []namedNode
	for page := 1; ; page++ {
		p, err := client.ListDataroomNodes(ctx, dataroomID, parentID, page, 50)
		if err != nil {
			return nil, err
		}
		for _, item := range p.Items {
			name, decErr := crypto.DecryptToString(item.Node.NameEnc, identity)
			if decErr != nil {
				continue
			}
			result = append(result, namedNode{name: name, item: item})
		}
		if page >= p.Pages {
			break
		}
	}

	return result, nil
}

// resolvePath resolves a unix-style path to the node ID of the final component.
// Returns nil for an empty path or "/", indicating the dataroom root.
func resolvePath(
	ctx context.Context, client *api.Client, dataroomID, nodePath string, identity *age.HybridIdentity,
) (*string, error) {
	nodePath = strings.TrimSpace(nodePath)
	if nodePath == "" || nodePath == "/" {
		return nil, nil
	}

	parts := strings.Split(strings.TrimPrefix(nodePath, "/"), "/")
	var currentParentID *string

	for depth, part := range parts {
		if part == "" {
			continue
		}
		found := false
		for page := 1; ; page++ {
			nodesPage, err := client.ListDataroomNodes(ctx, dataroomID, currentParentID, page, 50)
			if err != nil {
				return nil, fmt.Errorf("listing nodes at depth %d: %w", depth, err)
			}
			for _, item := range nodesPage.Items {
				name, decErr := crypto.DecryptToString(item.Node.NameEnc, identity)
				if decErr != nil {
					continue
				}
				if name == part {
					id := item.Node.ID
					currentParentID = &id
					found = true

					break
				}
			}
			if found || page >= nodesPage.Pages {
				break
			}
		}
		if !found {
			// Wrap os.ErrNotExist so the WebDAV handler maps a missing intermediate
			// path component to 404 instead of 500 (callers use errors.Is).
			return nil, fmt.Errorf("path not found: /%s: %w", strings.Join(parts[:depth+1], "/"), os.ErrNotExist)
		}
	}

	return currentParentID, nil
}

// resolvePathItem resolves a unix-style path to the full node item (including its
// current version) of the final component. It locates the parent via resolvePath,
// then lists the parent so the returned item carries node_version — which the
// single-node endpoint (GET /dataroom/node/{id}) does not return.
// Returns nil for an empty path or "/", indicating the dataroom root.
func resolvePathItem(
	ctx context.Context, client *api.Client, dataroomID, nodePath string, identity *age.HybridIdentity,
) (*api.DataroomNodeItem, error) {
	nodePath = strings.TrimSpace(nodePath)
	if strings.Trim(nodePath, "/") == "" {
		return nil, nil
	}

	parentPath, name := splitPathParent(nodePath)
	parentID, err := resolvePath(ctx, client, dataroomID, parentPath, identity)
	if err != nil {
		return nil, err
	}

	nodes, err := fetchNodesWithNames(ctx, client, dataroomID, parentID, identity)
	if err != nil {
		return nil, err
	}
	for _, nn := range nodes {
		if nn.name == name {
			item := nn.item

			return &item, nil
		}
	}

	return nil, fmt.Errorf("path not found: %s", nodePath)
}

// resolveGlob resolves a path that may contain glob patterns in any component.
func resolveGlob(
	ctx context.Context, client *api.Client, dataroomID, rawPath string, identity *age.HybridIdentity,
) ([]api.DataroomNodeItem, error) {
	var parts []string
	for _, p := range strings.Split(strings.TrimPrefix(strings.TrimSpace(rawPath), "/"), "/") {
		if p != "" {
			parts = append(parts, p)
		}
	}
	if len(parts) == 0 {
		return nil, nil
	}

	type cursor struct{ parentID *string }
	cursors := []cursor{{parentID: nil}}

	var finalItems []api.DataroomNodeItem

	for i, part := range parts {
		isLast := i == len(parts)-1
		isGlob := hasGlob(part)

		var nextCursors []cursor

		for _, cur := range cursors {
			nodes, err := fetchNodesWithNames(ctx, client, dataroomID, cur.parentID, identity)
			if err != nil {
				return nil, err
			}
			for _, nn := range nodes {
				var matches bool
				if isGlob {
					var matchErr error
					matches, matchErr = path.Match(part, nn.name)
					if matchErr != nil {
						return nil, fmt.Errorf("invalid glob pattern %q: %w", part, matchErr)
					}
				} else {
					matches = nn.name == part
				}
				if !matches {
					continue
				}
				if isLast {
					finalItems = append(finalItems, nn.item)
				} else {
					id := nn.item.Node.ID
					nextCursors = append(nextCursors, cursor{parentID: &id})
				}
			}
		}

		if !isLast {
			cursors = nextCursors
			if len(cursors) == 0 {
				return nil, fmt.Errorf("path not found: /%s", strings.Join(parts[:i+1], "/"))
			}
		}
	}

	return finalItems, nil
}

// findNodeAndTypeByName scans a folder for a node whose decrypted name matches name.
// It uses the listing (TypeEnc from ListDataroomNodes) rather than GetDataroomNode, because
// the GET /dataroom/node/{id} endpoint does not return type_enc in its response.
func findNodeAndTypeByName(
	ctx context.Context, client *api.Client, dataroomID string,
	parentID *string, name string, identity *age.HybridIdentity,
) (id string, isFile bool, err error) {
	nodes, err := fetchNodesWithNames(ctx, client, dataroomID, parentID, identity)
	if err != nil {
		return "", false, err
	}
	for _, nn := range nodes {
		if nn.name == name {
			return nn.item.Node.ID, nn.item.Node.TypeEnc != nil, nil
		}
	}

	return "", false, fmt.Errorf("node %q not found in folder", name)
}

// — Upload / download helpers —————————————————————————————————————————————————

// InitStreamUpload resolves the parent directory, creates the dataroom node and version,
// and returns the identifiers needed to stream chunks. Call UploadChunks next.
// newNode is true when a brand-new node was created; on upload failure after this call
// returns, callers must delete the node when newNode is true (a new version of an existing
// node is left as-is). This function only cleans up the node if version creation fails internally.
func InitStreamUpload(
	ctx context.Context,
	client *api.Client,
	dataroomID, parentPath, fileName string,
	totalSize int64,
	sess *DataroomSession,
) (nodeID, versionID string, newNode bool, err error) {
	parentID, err := resolvePath(ctx, client, dataroomID, parentPath, sess.Identity)
	if err != nil {
		return "", "", false, fmt.Errorf("resolving parent path: %w", err)
	}

	mimeType := mime.TypeByExtension(filepath.Ext(fileName))
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}

	nameEnc, err := crypto.EncryptStringForKeys(fileName, []string{sess.PublicKey})
	if err != nil {
		return "", "", false, fmt.Errorf("encrypting filename: %w", err)
	}
	typeEnc, err := crypto.EncryptStringForKeys(mimeType, []string{sess.PublicKey})
	if err != nil {
		return "", "", false, fmt.Errorf("encrypting MIME type: %w", err)
	}

	node, createErr := client.CreateDataroomNode(
		ctx, dataroomID, nameEnc, nodeNameHash(fileName, sess.NameSalt), &typeEnc, parentID,
	)
	var targetNodeID string
	isNewNode := createErr == nil

	if createErr != nil {
		if !isConflict(createErr) {
			return "", "", false, fmt.Errorf("creating file node: %w", createErr)
		}
		existingID, isFile, findErr := findNodeAndTypeByName(ctx, client, dataroomID, parentID, fileName, sess.Identity)
		if findErr != nil {
			return "", "", false, fmt.Errorf("node already exists but could not be located: %w", findErr)
		}
		if !isFile {
			return "", "", false, fmt.Errorf("cannot upload file %q: a folder with that name already exists", fileName)
		}
		targetNodeID = existingID
	} else {
		targetNodeID = node.ID
	}

	version, err := client.CreateDataroomNodeVersion(ctx, targetNodeID, totalSize, typeEnc)
	if err != nil {
		if isNewNode {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			_ = client.DeleteDataroomNode(cleanupCtx, targetNodeID)
			cancel()
		}

		return "", "", false, fmt.Errorf("creating node version: %w", err)
	}

	return targetNodeID, version.ID, isNewNode, nil
}

// uploadDataroomFile creates a file node (or adds a new version on 409) and uploads chunks.
//
//nolint:dupl
func uploadDataroomFile(
	ctx context.Context, client *api.Client, dataroomID, filePath string,
	parentID *string, sessionPubKey string, sessionIdentity *age.HybridIdentity,
	displayName, nameSalt string, progress ProgressFn,
) error {
	f, err := os.Open(filePath) //nolint:gosec // G304
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck

	info, err := f.Stat()
	if err != nil {
		return err
	}

	name := filepath.Base(filePath)
	if displayName == "" {
		displayName = name
	}
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

	node, createErr := client.CreateDataroomNode(
		ctx, dataroomID, nameEnc, nodeNameHash(name, nameSalt), &typeEnc, parentID,
	)
	var targetNodeID string
	newNode := createErr == nil

	if createErr != nil {
		if !isConflict(createErr) {
			return fmt.Errorf("creating file node: %w", createErr)
		}
		existingID, isFile, findErr := findNodeAndTypeByName(ctx, client, dataroomID, parentID, name, sessionIdentity)
		if findErr != nil {
			return fmt.Errorf("node already exists but could not be located: %w", findErr)
		}
		if !isFile {
			return fmt.Errorf("cannot upload file %q: a folder with that name already exists", name)
		}
		fmt.Fprintf(os.Stderr, "  %s: adding new version\n", displayName)
		targetNodeID = existingID
	} else {
		targetNodeID = node.ID
	}

	version, err := client.CreateDataroomNodeVersion(ctx, targetNodeID, info.Size(), typeEnc)
	if err != nil {
		return fmt.Errorf("creating node version: %w", err)
	}

	uploadErr := UploadChunks(ctx, f, info.Size(), displayName, sessionPubKey, progress,
		func(ctx context.Context, chunkID int, data []byte) error {
			return client.UploadDataroomChunk(ctx, version.ID, chunkID, data)
		})
	if uploadErr != nil && newNode {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		if delErr := client.DeleteDataroomNode(cleanupCtx, targetNodeID); delErr == nil {
			fmt.Fprintf(os.Stderr, "  cleaned up: %s\n", displayName)
		}
		cleanupCancel()
	}

	return uploadErr
}

type dirQueueEntry struct {
	localPath    string
	remoteParent *string
	relPath      string
}

// uploadDataroomDir recursively uploads a local directory into the dataroom using BFS.
func uploadDataroomDir(
	ctx context.Context, client *api.Client, dataroomID, localDir string,
	parentID *string, sessionPubKey string, sessionIdentity *age.HybridIdentity, nameSalt string,
	progress ProgressFn,
) error {
	queue := []dirQueueEntry{{localPath: localDir, remoteParent: parentID, relPath: filepath.Base(localDir)}}

	for len(queue) > 0 {
		entry := queue[0]
		queue = queue[1:]

		entries, err := os.ReadDir(entry.localPath) //nolint:gosec // G304
		if err != nil {
			return fmt.Errorf("reading directory %s: %w", entry.localPath, err)
		}

		for _, e := range entries {
			fullPath := filepath.Join(entry.localPath, e.Name())
			relPath := filepath.Join(entry.relPath, e.Name())

			if e.IsDir() {
				nameEnc, err := crypto.EncryptStringForKeys(e.Name(), []string{sessionPubKey})
				if err != nil {
					return fmt.Errorf("encrypting dir name: %w", err)
				}
				node, createErr := client.CreateDataroomNode(
					ctx, dataroomID, nameEnc, nodeNameHash(e.Name(), nameSalt), nil, entry.remoteParent,
				)
				var folderID string
				if createErr != nil {
					if !isConflict(createErr) {
						return fmt.Errorf("creating folder %s: %w", e.Name(), createErr)
					}
					existingID, isFile, findErr := findNodeAndTypeByName(
						ctx, client, dataroomID, entry.remoteParent, e.Name(), sessionIdentity,
					)
					if findErr != nil {
						return fmt.Errorf("folder %s already exists but could not be located: %w", e.Name(), findErr)
					}
					if isFile {
						return fmt.Errorf("cannot create folder %q: a file with that name already exists", e.Name())
					}
					folderID = existingID
				} else {
					folderID = node.ID
				}
				queue = append(queue, dirQueueEntry{localPath: fullPath, remoteParent: &folderID, relPath: relPath})
			} else {
				if err := uploadDataroomFile(
					ctx, client, dataroomID, fullPath, entry.remoteParent,
					sessionPubKey, sessionIdentity, relPath, nameSalt, progress,
				); err != nil {
					return fmt.Errorf("%s: %w", relPath, err)
				}
			}
		}
	}

	return nil
}

// — Public service functions —————————————————————————————————————————————————

// ListDatarooms returns a page of the authenticated user's datarooms.
func ListDatarooms(ctx context.Context, client *api.Client) (*ListDataroomsResult, error) {
	result, err := client.ListDatarooms(ctx, 1)
	if err != nil {
		return nil, fmt.Errorf("listing datarooms: %w", err)
	}

	return &ListDataroomsResult{
		Items: result.Items,
		Total: result.Total,
		Pages: result.Pages,
		Page:  result.Page,
	}, nil
}

// CreateDataroom creates a new dataroom with the given title.
// reader is used to obtain the user's AGE key passphrase.
func CreateDataroom(
	ctx context.Context, cfg *config.Config, client *api.Client, title string, reader PassphraseReader,
) (*CreateDataroomResult, error) {
	userKey, err := client.GetActiveKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching encryption key: %w", err)
	}
	if userKey == nil {
		return nil, fmt.Errorf("no active encryption key - set up your key in the web interface first")
	}

	sessionIdentity, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generating session key: %w", err)
	}
	sessionPrivKey := sessionIdentity.String()
	sessionPubKey := sessionIdentity.Recipient().String()

	sessionPrivKeyEnc, err := crypto.EncryptStringForKeys(sessionPrivKey, []string{userKey.PublicKey})
	if err != nil {
		return nil, fmt.Errorf("encrypting session key: %w", err)
	}

	saltBytes := make([]byte, 16)
	if _, err := cryptorand.Read(saltBytes); err != nil {
		return nil, fmt.Errorf("generating name salt: %w", err)
	}
	nameSalt := hex.EncodeToString(saltBytes)
	nameSaltEnc, err := crypto.EncryptStringForKeys(nameSalt, []string{sessionPubKey})
	if err != nil {
		return nil, fmt.Errorf("encrypting name salt: %w", err)
	}

	dr, err := client.CreateDataroom(ctx, title, sessionPrivKeyEnc, sessionPubKey, &nameSaltEnc)
	if err != nil {
		return nil, fmt.Errorf("creating dataroom: %w", err)
	}

	return &CreateDataroomResult{ID: dr.ID, Title: dr.Title}, nil
}

// GetDataroomInfo fetches metadata, stats, and users for a dataroom in parallel.
func GetDataroomInfo(ctx context.Context, client *api.Client, dataroomID string) (*DataroomInfoResult, error) {
	type drResult struct {
		v   *api.Dataroom
		err error
	}
	type statsResult struct {
		v   *api.DataroomStats
		err error
	}
	type usersResult struct {
		v   []api.DataroomUser
		err error
	}

	drCh := make(chan drResult, 1)
	statsCh := make(chan statsResult, 1)
	usersCh := make(chan usersResult, 1)

	go func() { v, err := client.GetDataroom(ctx, dataroomID); drCh <- drResult{v, err} }()
	go func() { v, err := client.GetDataroomStats(ctx, dataroomID); statsCh <- statsResult{v, err} }()
	go func() { v, err := client.GetDataroomUsers(ctx, dataroomID); usersCh <- usersResult{v, err} }()

	dr := <-drCh
	stats := <-statsCh
	users := <-usersCh

	if dr.err != nil {
		return nil, fmt.Errorf("fetching dataroom: %w", dr.err)
	}
	if stats.err != nil {
		return nil, fmt.Errorf("fetching stats: %w", stats.err)
	}
	if users.err != nil {
		return nil, fmt.Errorf("fetching users: %w", users.err)
	}

	return &DataroomInfoResult{
		Dataroom: dr.v,
		Stats:    stats.v,
		Users:    users.v,
	}, nil
}

// ListNodes lists all nodes at a given retyc:// URI, decrypting names.
// Glob patterns in the path are supported.
func ListNodes(
	ctx context.Context, cfg *config.Config, client *api.Client, uri string, reader PassphraseReader,
) ([]DataroomNodeInfo, error) {
	parsed, err := ParseRetycURI(uri)
	if err != nil {
		return nil, err
	}

	sess, err := resolveDataroomSession(ctx, cfg, client, parsed.DataroomID, reader)
	if err != nil {
		return nil, err
	}

	return ListNodesWithSession(ctx, client, parsed.DataroomID, parsed.Path, sess)
}

// UploadToDataroom uploads one or more local paths into a remote retyc:// URI.
// Directories are uploaded recursively.
func UploadToDataroom(
	ctx context.Context, cfg *config.Config, client *api.Client,
	localPaths []string, remoteURI string, reader PassphraseReader, progress ProgressFn,
) error {
	dst, err := ParseRetycURI(remoteURI)
	if err != nil {
		return err
	}

	sess, err := resolveDataroomSession(ctx, cfg, client, dst.DataroomID, reader)
	if err != nil {
		return err
	}

	return UploadToDataroomWithSession(ctx, client, dst.DataroomID, dst.Path, localPaths, sess, progress)
}

// UploadToDataroomWithSession is UploadToDataroom for callers that already hold
// the dataroom session (the WebDAV server caches it per dataroom).
func UploadToDataroomWithSession(
	ctx context.Context, client *api.Client, dataroomID, dstPath string,
	localPaths []string, sess *DataroomSession, progress ProgressFn,
) error {
	destParentID, err := resolvePath(ctx, client, dataroomID, dstPath, sess.Identity)
	if err != nil {
		return err
	}

	for _, localPath := range localPaths {
		info, err := os.Stat(localPath)
		if err != nil {
			return err
		}
		if info.IsDir() {
			if err := uploadDataroomDir(
				ctx, client, dataroomID, localPath, destParentID,
				sess.PublicKey, sess.Identity, sess.NameSalt, progress,
			); err != nil {
				return fmt.Errorf("%s: %w", info.Name(), err)
			}
		} else {
			if err := uploadDataroomFile(
				ctx, client, dataroomID, localPath, destParentID,
				sess.PublicKey, sess.Identity, "", sess.NameSalt, progress,
			); err != nil {
				return fmt.Errorf("%s: %w", info.Name(), err)
			}
		}
	}

	return nil
}

// DownloadFromDataroom downloads a file (or glob of files) from a retyc:// URI.
func DownloadFromDataroom(
	ctx context.Context, cfg *config.Config, client *api.Client,
	remoteURI, localDir string, reader PassphraseReader, progress ProgressFn,
) ([]string, error) {
	src, err := ParseRetycURI(remoteURI)
	if err != nil {
		return nil, err
	}

	sess, err := resolveDataroomSession(ctx, cfg, client, src.DataroomID, reader)
	if err != nil {
		return nil, err
	}

	outputDir := localDir
	if outputDir == "" {
		outputDir = "."
	}
	if err := os.MkdirAll(outputDir, 0700); err != nil {
		return nil, fmt.Errorf("creating output directory: %w", err)
	}

	var downloaded []string

	if hasGlob(src.Path) {
		matches, err := resolveGlob(ctx, client, src.DataroomID, src.Path, sess.Identity)
		if err != nil {
			return nil, err
		}
		if len(matches) == 0 {
			return nil, fmt.Errorf("no nodes match %s", src.Path)
		}
		for _, item := range matches {
			if item.Node.TypeEnc == nil || item.Version == nil {
				continue
			}
			name, decErr := crypto.DecryptToString(item.Node.NameEnc, sess.Identity)
			if decErr != nil {
				name = item.Node.ID
			}
			if err := DownloadChunks(
				ctx, outputDir, name,
				item.Version.OriginalSize, item.Version.ChunkCount, sess.Identity, progress,
				func(ctx context.Context, chunkID int) ([]byte, error) {
					return client.DownloadDataroomChunk(ctx, item.Version.ID, chunkID)
				},
			); err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			downloaded = append(downloaded, filepath.Join(outputDir, filepath.Base(name)))
		}

		return downloaded, nil
	}

	item, err := resolvePathItem(ctx, client, src.DataroomID, src.Path, sess.Identity)
	if err != nil {
		return nil, err
	}
	if item == nil {
		return nil, fmt.Errorf("cannot download the root folder")
	}
	if item.Node.TypeEnc == nil {
		return nil, fmt.Errorf("%s is a folder — use `ls` to browse it", src.Path)
	}
	if item.Version == nil {
		return nil, fmt.Errorf("node has no version yet")
	}

	name, err := crypto.DecryptToString(item.Node.NameEnc, sess.Identity)
	if err != nil {
		name = item.Node.ID
	}

	if err := DownloadChunks(
		ctx, outputDir, name,
		item.Version.OriginalSize, item.Version.ChunkCount, sess.Identity, progress,
		func(ctx context.Context, chunkID int) ([]byte, error) {
			return client.DownloadDataroomChunk(ctx, item.Version.ID, chunkID)
		},
	); err != nil {
		return nil, err
	}

	downloaded = append(downloaded, filepath.Join(outputDir, filepath.Base(name)))

	return downloaded, nil
}

// MkdirDataroom creates a folder at the given retyc:// URI.
// Returns the new node ID.
func MkdirDataroom(
	ctx context.Context, cfg *config.Config, client *api.Client, uri string, reader PassphraseReader,
) (string, error) {
	parsed, err := ParseRetycURI(uri)
	if err != nil {
		return "", err
	}

	sess, err := resolveDataroomSession(ctx, cfg, client, parsed.DataroomID, reader)
	if err != nil {
		return "", err
	}

	return MkdirDataroomWithSession(ctx, client, parsed.DataroomID, parsed.Path, sess)
}

// MkdirDataroomWithSession is MkdirDataroom for callers that already hold the
// dataroom session.
func MkdirDataroomWithSession(
	ctx context.Context, client *api.Client, dataroomID, nodePath string, sess *DataroomSession,
) (string, error) {
	parentPath, name := splitPathParent(nodePath)
	if name == "" {
		return "", fmt.Errorf("path must include a folder name: %s", nodePath)
	}

	parentID, err := resolvePath(ctx, client, dataroomID, parentPath, sess.Identity)
	if err != nil {
		return "", err
	}

	nameEnc, err := crypto.EncryptStringForKeys(name, []string{sess.PublicKey})
	if err != nil {
		return "", fmt.Errorf("encrypting folder name: %w", err)
	}

	node, err := client.CreateDataroomNode(
		ctx, dataroomID, nameEnc, nodeNameHash(name, sess.NameSalt), nil, parentID,
	)
	if err != nil {
		return "", fmt.Errorf("creating folder: %w", err)
	}

	return node.ID, nil
}

// DeleteDataroomNode deletes a node (or whole dataroom) at the given retyc:// URI.
// Glob patterns expand to multiple deletions. Returns the count of deleted items.
func DeleteDataroomNode(
	ctx context.Context, cfg *config.Config, client *api.Client, uri string, reader PassphraseReader,
) (int, error) {
	parsed, err := ParseRetycURI(uri)
	if err != nil {
		return 0, err
	}

	if parsed.Path == "/" {
		if err := client.DeleteDataroom(ctx, parsed.DataroomID); err != nil {
			return 0, fmt.Errorf("deleting dataroom: %w", err)
		}

		return 1, nil
	}

	sess, err := resolveDataroomSession(ctx, cfg, client, parsed.DataroomID, reader)
	if err != nil {
		return 0, err
	}

	return DeleteDataroomNodeWithSession(ctx, client, parsed.DataroomID, parsed.Path, sess)
}

// DeleteDataroomNodeWithSession deletes the node(s) at nodePath (glob allowed)
// for callers that already hold the dataroom session. Deleting the dataroom
// itself ("/") needs no session and stays in DeleteDataroomNode.
func DeleteDataroomNodeWithSession(
	ctx context.Context, client *api.Client, dataroomID, nodePath string, sess *DataroomSession,
) (int, error) {
	if hasGlob(nodePath) {
		matches, err := resolveGlob(ctx, client, dataroomID, nodePath, sess.Identity)
		if err != nil {
			return 0, err
		}
		if len(matches) == 0 {
			return 0, fmt.Errorf("no nodes match %s", nodePath)
		}
		for _, item := range matches {
			if err := client.DeleteDataroomNode(ctx, item.Node.ID); err != nil {
				return 0, fmt.Errorf("deleting %s: %w", item.Node.ID, err)
			}
		}

		return len(matches), nil
	}

	nodeID, err := resolvePath(ctx, client, dataroomID, nodePath, sess.Identity)
	if err != nil {
		return 0, err
	}
	if nodeID == nil {
		return 0, fmt.Errorf("cannot delete the root folder")
	}
	if err := client.DeleteDataroomNode(ctx, *nodeID); err != nil {
		return 0, fmt.Errorf("deleting node: %w", err)
	}

	return 1, nil
}

// MoveDataroomNode renames or moves a node within the same dataroom.
func MoveDataroomNode(
	ctx context.Context, cfg *config.Config, client *api.Client, srcURI, dstURI string, reader PassphraseReader,
) error {
	src, err := ParseRetycURI(srcURI)
	if err != nil {
		return fmt.Errorf("source: %w", err)
	}
	dst, err := ParseRetycURI(dstURI)
	if err != nil {
		return fmt.Errorf("destination: %w", err)
	}
	if src.DataroomID != dst.DataroomID {
		return fmt.Errorf("source and destination must be in the same dataroom")
	}

	sess, err := resolveDataroomSession(ctx, cfg, client, src.DataroomID, reader)
	if err != nil {
		return err
	}

	return MoveDataroomNodeWithSession(ctx, client, src.DataroomID, src.Path, dst.Path, sess)
}

// MoveDataroomNodeWithSession renames/moves srcPath to dstPath within one
// dataroom for callers that already hold the dataroom session.
func MoveDataroomNodeWithSession(
	ctx context.Context, client *api.Client, dataroomID, srcPath, dstPath string, sess *DataroomSession,
) error {
	srcNodeID, err := resolvePath(ctx, client, dataroomID, srcPath, sess.Identity)
	if err != nil {
		return err
	}
	if srcNodeID == nil {
		return fmt.Errorf("cannot move the root folder")
	}

	dstParentPath, newName := splitPathParent(dstPath)
	if newName == "" {
		return fmt.Errorf("destination path must include a name: %s", dstPath)
	}

	dstParentID, err := resolvePath(ctx, client, dataroomID, dstParentPath, sess.Identity)
	if err != nil {
		return err
	}

	nameEnc, err := crypto.EncryptStringForKeys(newName, []string{sess.PublicKey})
	if err != nil {
		return fmt.Errorf("encrypting new name: %w", err)
	}

	if err := client.UpdateDataroomNode(
		ctx, *srcNodeID, nameEnc, nodeNameHash(newName, sess.NameSalt), dstParentID,
	); err != nil {
		return fmt.Errorf("moving node: %w", err)
	}

	return nil
}

// AddDataroomUser adds a user to the dataroom and rekeys it for all current members.
func AddDataroomUser(
	ctx context.Context, cfg *config.Config, client *api.Client,
	dataroomID, email, role string, reader PassphraseReader,
) error {
	sess, err := resolveDataroomSession(ctx, cfg, client, dataroomID, reader)
	if err != nil {
		return err
	}

	if _, err := client.AddDataroomUser(ctx, dataroomID, email, role); err != nil {
		return fmt.Errorf("adding user: %w", err)
	}

	return rekeyDataroom(ctx, client, dataroomID, sess.PrivateKey, email)
}

// RemoveDataroomUser removes a user from the dataroom and rekeys it for remaining members.
func RemoveDataroomUser(
	ctx context.Context, cfg *config.Config, client *api.Client,
	dataroomID, userID string, reader PassphraseReader,
) error {
	sess, err := resolveDataroomSession(ctx, cfg, client, dataroomID, reader)
	if err != nil {
		return err
	}

	if err := client.RemoveDataroomUser(ctx, dataroomID, userID); err != nil {
		return fmt.Errorf("removing user: %w", err)
	}

	return rekeyDataroom(ctx, client, dataroomID, sess.PrivateKey, "")
}

// rekeyDataroom re-encrypts the session private key for all current dataroom members.
// subject is informational (email for add, empty for remove) and used only in warning messages.
func rekeyDataroom(ctx context.Context, client *api.Client, dataroomID, sessionPrivKey, subject string) error {
	users, err := client.GetDataroomUsers(ctx, dataroomID)
	if err != nil {
		return fmt.Errorf("fetching users for rekey: %w", err)
	}

	pubKeys := make([]string, 0, len(users))
	for _, u := range users {
		if u.CurrentPublicKey != nil {
			pubKeys = append(pubKeys, *u.CurrentPublicKey)
		} else if u.PublicKey != "" {
			pubKeys = append(pubKeys, u.PublicKey)
		}
	}

	if len(pubKeys) == 0 {
		return nil
	}

	newEnc, err := crypto.EncryptStringForKeys(sessionPrivKey, pubKeys)
	if err != nil {
		return fmt.Errorf("encrypting session key: %w", err)
	}

	if err := client.RekeyDataroom(ctx, dataroomID, newEnc); err != nil {
		if subject != "" {
			fmt.Fprintf(os.Stderr,
				"warning: %s was added but key rotation failed — "+
					"they cannot access existing content until you re-run this command\n", subject)
		} else {
			fmt.Fprintf(os.Stderr,
				"warning: user was removed but key rotation failed — "+
					"their access may persist until you re-run this command\n")
		}

		return fmt.Errorf("rekeying dataroom: %w", err)
	}

	return nil
}

package service

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/config"
	"github.com/retyc/retyc-cli/internal/crypto"
	"github.com/retyc/retyc-cli/internal/telemetry"
	"go.opentelemetry.io/otel/trace"
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
	// mime is the dataroom's MIME table, loaded on first use (see mimeCache).
	// Sessions are shared by pointer (SessionCache), never copied.
	mime mimeCache
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

	userIdentity, err := ResolveUserIdentity(ctx, cfg, kr.v, reader)
	if err != nil {
		return nil, err
	}

	return buildDataroomSession(dr.v, userIdentity)
}

// buildDataroomSession decrypts the dataroom's session key and per-dataroom
// name salt with an already unlocked user identity.
func buildDataroomSession(dr *api.Dataroom, userIdentity *age.HybridIdentity) (*dataroomSession, error) {
	sessionPrivKey, err := crypto.DecryptToString(dr.SessionPrivateKeyEnc, userIdentity)
	if err != nil {
		return nil, fmt.Errorf("decrypting dataroom session key: %w", err)
	}

	sessionIdentity, err := crypto.ParseIdentity(sessionPrivKey)
	if err != nil {
		return nil, fmt.Errorf("parsing session AGE identity: %w", err)
	}

	var nameSalt string
	if dr.NodeNameSaltEnc != nil {
		nameSalt, err = crypto.DecryptToString(*dr.NodeNameSaltEnc, sessionIdentity)
		if err != nil {
			return nil, fmt.Errorf("decrypting name salt: %w", err)
		}
	}

	return &dataroomSession{
		Identity:   sessionIdentity,
		PublicKey:  dr.SessionPublicKey,
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

// GetDataroomSessionWithIdentity resolves the cryptographic session for a
// dataroom using an already unlocked user identity (see UnlockUserIdentity):
// one API call, no user-key fetch, no passphrase, no scrypt.
func GetDataroomSessionWithIdentity(
	ctx context.Context, client *api.Client, dataroomID string, userIdentity *age.HybridIdentity,
) (*DataroomSession, error) {
	dr, err := client.GetDataroom(ctx, dataroomID)
	if err != nil {
		return nil, fmt.Errorf("fetching dataroom: %w", err)
	}

	return buildDataroomSession(dr, userIdentity)
}

// fetchNodeItems lists the raw API node items at nodePath, supporting glob patterns.
// It is the shared fetch path behind ListNodes and ListNodesWithSession.
func fetchNodeItems(
	ctx context.Context, client *api.Client, dataroomID, nodePath string, sess *dataroomSession,
) ([]api.DataroomNodeItem, error) {
	if hasGlob(nodePath) {
		return resolveGlob(ctx, client, dataroomID, nodePath, sess.Identity)
	}

	return fetchChildItems(ctx, client, dataroomID, nodePath, sess)
}

// fetchChildItems lists the raw API node items under the folder at nodePath,
// resolved literally (no glob interpretation).
func fetchChildItems(
	ctx context.Context, client *api.Client, dataroomID, nodePath string, sess *dataroomSession,
) ([]api.DataroomNodeItem, error) {
	parentID, err := resolvePathWithSession(ctx, client, dataroomID, nodePath, sess)
	if err != nil {
		return nil, err
	}

	return fetchChildItemsByID(ctx, client, dataroomID, parentID)
}

// fetchChildItemsByID lists every page of the children of parentID (nil for
// the dataroom root), pages fetched concurrently (see fetchAllPages).
func fetchChildItemsByID(
	ctx context.Context, client *api.Client, dataroomID string, parentID *string,
) ([]api.DataroomNodeItem, error) {
	pages, err := fetchAllPages(ctx, nodePageFetcher(client, dataroomID, parentID),
		func(_ context.Context, items []api.DataroomNodeItem) []api.DataroomNodeItem { return items })
	if err != nil {
		return nil, err
	}

	return slices.Concat(pages...), nil
}

// nodePageFetcher returns the fetch step of fetchAllPages for the children of
// parentID: one page of nodeListPageSize raw items and the reported page count.
func nodePageFetcher(
	client *api.Client, dataroomID string, parentID *string,
) func(ctx context.Context, page int) ([]api.DataroomNodeItem, int, error) {
	return func(ctx context.Context, page int) ([]api.DataroomNodeItem, int, error) {
		pg, err := client.ListDataroomNodes(ctx, dataroomID, parentID, page, nodeListPageSize)
		if err != nil {
			return nil, 0, err
		}

		return pg.Items, pg.Pages, nil
	}
}

// nodesFromItems decrypts API node items into DataroomNodeInfo with the
// session's keys. client and dataroomID serve to resolve MIME table rows;
// client may be nil for items that carry no row (legacy ciphertexts).
func nodesFromItems(
	ctx context.Context, client *api.Client, dataroomID string, items []api.DataroomNodeItem, sess *dataroomSession,
) []DataroomNodeInfo {
	// One span per call under the caller's span (a listing, or one page of it
	// when pages are decrypted as they arrive): the node count only.
	_, span := telemetry.Tracer().Start(ctx, "crypto.decrypt_names",
		trace.WithAttributes(telemetry.AttrNodeCount.Int(len(items))))
	defer span.End()
	result := make([]DataroomNodeInfo, 0, len(items))
	for i := range items {
		result = append(result, nodeFromItem(ctx, client, dataroomID, &items[i], sess))
	}

	return result
}

// nodeFromItem decrypts one API node item. A folder's modification time is
// its creation time; a file's is the one its uploader declared, or the
// version's creation time.
func nodeFromItem(
	ctx context.Context, client *api.Client, dataroomID string, item *api.DataroomNodeItem, sess *dataroomSession,
) DataroomNodeInfo {
	name, decErr := crypto.DecryptToString(item.Node.NameEnc, sess.Identity)
	if decErr != nil {
		name = "(encrypted)"
	}
	info := DataroomNodeInfo{ID: item.Node.ID, Name: name, Type: "dir", modTime: item.Node.CreatedAt}
	if mode, ok := api.ParseAccessMode(item.Node.AccessMode); ok {
		info.mode = mode
	}
	if item.Node.IsFolder() {
		return info
	}
	info.Type = "file"
	info.MIMEType = sess.mimeTypeOf(ctx, client, dataroomID, &item.Node)
	if item.Version != nil {
		info.Size = item.Version.OriginalSize
		info.VersionID = item.Version.ID
		info.ChunkCount = item.Version.ChunkCount
		info.modTime = item.Version.ModTime()
	}

	return info
}

// ListNodesWithSession lists all nodes at the given path using a pre-resolved session,
// avoiding the redundant resolveDataroomSession call in ListNodes.
func ListNodesWithSession(
	ctx context.Context, client *api.Client, dataroomID, nodePath string, sess *DataroomSession,
) ([]DataroomNodeInfo, error) {
	items, err := fetchNodeItems(ctx, client, dataroomID, nodePath, sess)
	if err != nil {
		return nil, err
	}

	return nodesFromItems(ctx, client, dataroomID, items, sess), nil
}

// ListNodesLiteralWithSession lists the children of the folder at nodePath,
// resolving every path component by its exact name. Callers that relay
// client-supplied paths (WebDAV) use it: a folder legitimately named "v[1]"
// or "q?" must list its children, not be matched as a pattern against itself.
func ListNodesLiteralWithSession(
	ctx context.Context, client *api.Client, dataroomID, nodePath string, sess *DataroomSession,
) ([]DataroomNodeInfo, error) {
	items, err := fetchChildItems(ctx, client, dataroomID, nodePath, sess)
	if err != nil {
		return nil, err
	}

	return nodesFromItems(ctx, client, dataroomID, items, sess), nil
}

// ListNodesByIDWithSession lists the children of the folder parentID (nil for
// the dataroom root), for callers that already know its ID and so need no path
// resolution.
func ListNodesByIDWithSession(
	ctx context.Context, client *api.Client, dataroomID string, parentID *string, sess *DataroomSession,
) ([]DataroomNodeInfo, error) {
	nodes, _, err := ListNodesByIDIfChanged(ctx, client, dataroomID, parentID, sess, "")

	return nodes, err
}

// ListNodesByIDIfChanged is ListNodesByIDWithSession for a caller that kept
// the listing of the folder and the ETag it came with: when the dataroom has
// not changed since, it answers api.ErrNotModified after one round trip,
// without a page fetched or a name decrypted. It returns the ETag to keep
// with the new listing, "" on an API that sends none.
func ListNodesByIDIfChanged(
	ctx context.Context, client *api.Client, dataroomID string, parentID *string, sess *DataroomSession, etag string,
) ([]DataroomNodeInfo, string, error) {
	// Only the first page is conditional, and its ETag is the one kept: it is
	// fetched alone, before the others, so a change landing between two pages
	// leaves an ETag older than the listing, which the next call refreshes.
	var newETag string
	fetch := func(ctx context.Context, page int) ([]api.DataroomNodeItem, int, error) {
		condition := ""
		if page == 1 {
			condition = etag
		}
		pg, pageETag, err := client.ListDataroomNodesIfChanged(
			ctx, dataroomID, parentID, page, nodeListPageSize, condition)
		if err != nil {
			return nil, 0, err
		}
		if page == 1 {
			newETag = pageETag
		}

		return pg.Items, pg.Pages, nil
	}
	// Each page is decrypted as soon as it arrives, in parallel with the other
	// pages and outside the fetch slots (see fetchAllPages).
	pages, err := fetchAllPages(ctx, fetch,
		func(ctx context.Context, items []api.DataroomNodeItem) []DataroomNodeInfo {
			return nodesFromItems(ctx, client, dataroomID, items, sess)
		})
	if err != nil {
		return nil, "", err
	}

	return slices.Concat(pages...), newETag, nil
}

// — Node traversal helpers ————————————————————————————————————————————————————

// namedNode pairs a decrypted name with its API item.
type namedNode struct {
	name string
	item api.DataroomNodeItem
}

// fetchNodesWithNames lists all paginated nodes in a folder and decrypts their
// names, each page as soon as it arrives (see fetchAllPages).
func fetchNodesWithNames(
	ctx context.Context, client *api.Client, dataroomID string, parentID *string, identity *age.HybridIdentity,
) ([]namedNode, error) {
	pages, err := fetchAllPages(ctx, nodePageFetcher(client, dataroomID, parentID),
		func(_ context.Context, items []api.DataroomNodeItem) []namedNode {
			named := make([]namedNode, 0, len(items))
			for _, item := range items {
				name, decErr := crypto.DecryptToString(item.Node.NameEnc, identity)
				if decErr != nil {
					continue
				}
				named = append(named, namedNode{name: name, item: item})
			}

			return named
		})
	if err != nil {
		return nil, err
	}

	return slices.Concat(pages...), nil
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
	trace.SpanFromContext(ctx).AddEvent("dataroom.resolve_path",
		trace.WithAttributes(telemetry.AttrPathDepth.Int(len(parts))))
	var currentParentID *string

	for depth, part := range parts {
		if part == "" {
			continue
		}
		found := false
		for page := 1; ; page++ {
			nodesPage, err := client.ListDataroomNodes(ctx, dataroomID, currentParentID, page, nodeListPageSize)
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
					// The last component wins: the span ends up tagged with the
					// node the path resolves to.
					trace.SpanFromContext(ctx).SetAttributes(telemetry.AttrNodeID.String(id))

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

// resolvePathWithSession is resolvePath for callers holding the session. On
// an API that indexes nodes by name hash it costs one lookup per path
// component, whatever the folders' sizes, and decrypts nothing; on an older
// API it falls back to resolvePath, which lists and decrypts each level.
func resolvePathWithSession(
	ctx context.Context, client *api.Client, dataroomID, nodePath string, sess *dataroomSession,
) (*string, error) {
	item, err := resolvePathItemWithSession(ctx, client, dataroomID, nodePath, sess)
	if err != nil || item == nil {
		return nil, err
	}
	id := item.Node.ID

	return &id, nil
}

// resolvePathItemWithSession resolves a unix-style path to the full node item
// (current version included) of its final component, nil for the root. It
// looks each component up by name hash when the API supports it, and lists
// the parent otherwise.
func resolvePathItemWithSession(
	ctx context.Context, client *api.Client, dataroomID, nodePath string, sess *dataroomSession,
) (*api.DataroomNodeItem, error) {
	nodePath = strings.TrimSpace(nodePath)
	if strings.Trim(nodePath, "/") == "" {
		return nil, nil
	}
	if !sess.supportsNodeTypes(ctx, client, dataroomID) {
		return resolvePathItem(ctx, client, dataroomID, nodePath, sess.Identity)
	}

	parts := strings.Split(strings.TrimPrefix(nodePath, "/"), "/")
	trace.SpanFromContext(ctx).AddEvent("dataroom.resolve_path",
		trace.WithAttributes(telemetry.AttrPathDepth.Int(len(parts))))
	var parentID *string
	var item *api.DataroomNodeItem
	for depth, part := range parts {
		if part == "" {
			continue
		}
		found, err := client.FindDataroomNodeByHash(ctx, dataroomID, parentID, nodeNameHash(part, sess.NameSalt))
		if err != nil {
			return nil, fmt.Errorf("looking up node at depth %d: %w", depth, err)
		}
		if found == nil {
			return nil, fmt.Errorf("path not found: /%s: %w", strings.Join(parts[:depth+1], "/"), os.ErrNotExist)
		}
		item = found
		id := found.Node.ID
		parentID = &id
		// The last component wins: the span ends up tagged with the node
		// the path resolves to.
		trace.SpanFromContext(ctx).SetAttributes(telemetry.AttrNodeID.String(id))
	}

	return item, nil
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

	return nil, fmt.Errorf("path not found: %s: %w", nodePath, os.ErrNotExist)
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

// ErrNameBeingDeleted reports a name the API still reserves for a deleted node.
//
// Deleting a node only marks it: the async purge removes the row later, and
// until then the folder's name uniqueness still counts it. Creating a node of
// that name answers 409, yet no listing shows the node it conflicts with. The
// window is seconds with the workers keeping up, longer when their queue lags.
var ErrNameBeingDeleted = errors.New(
	"a node of that name was deleted and the server has not released the name yet; retry in a moment")

// findNodeAndTypeByName finds the node named name in a folder: by name hash
// when the API supports the lookup, by listing and decrypting the folder
// otherwise.
//
// Callers reach it after a 409 on creation, so a miss means the conflicting
// node is one pending purge: ErrNameBeingDeleted.
func findNodeAndTypeByName(
	ctx context.Context, client *api.Client, dataroomID string,
	parentID *string, name string, sess *dataroomSession,
) (id string, isFile bool, err error) {
	if sess.supportsNodeTypes(ctx, client, dataroomID) {
		item, err := client.FindDataroomNodeByHash(ctx, dataroomID, parentID, nodeNameHash(name, sess.NameSalt))
		if err != nil {
			return "", false, err
		}
		if item == nil {
			return "", false, fmt.Errorf("%q: %w", name, ErrNameBeingDeleted)
		}

		return item.Node.ID, !item.Node.IsFolder(), nil
	}
	nodes, err := fetchNodesWithNames(ctx, client, dataroomID, parentID, sess.Identity)
	if err != nil {
		return "", false, err
	}
	for _, nn := range nodes {
		if nn.name == name {
			return nn.item.Node.ID, !nn.item.Node.IsFolder(), nil
		}
	}

	return "", false, fmt.Errorf("%q: %w", name, ErrNameBeingDeleted)
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
	parentID, err := resolvePathWithSession(ctx, client, dataroomID, parentPath, sess)
	if err != nil {
		return "", "", false, fmt.Errorf("resolving parent path: %w", err)
	}

	init, err := InitStreamUploadInto(ctx, client, dataroomID, parentID, fileName, totalSize, sess)

	return init.NodeID, init.VersionID, init.NewNode, err
}

// StreamUploadInit describes the node and version created for a streaming
// upload. It carries every field a later listing would report for that node, so
// a caller holding a cached listing can refresh its entry without guessing.
type StreamUploadInit struct {
	NodeID    string
	VersionID string
	MIMEType  string    // MIME type stored with the node
	CreatedAt time.Time // version creation time, as ListNodes will report it
	NewNode   bool      // node created here; callers delete it on upload failure
}

// DiscardFailedUpload removes what a failed upload left behind: the whole node
// when the upload created it, otherwise only the version it added, so that the
// node's earlier versions survive. A failed version can never be completed —
// stored chunks are immutable and the API refuses any index beyond the count
// announced at creation — so left in place it only clutters the history.
//
// It runs detached from the upload context, which is usually cancelled by then,
// on its own short timeout. It is best-effort: deleting requires the can_delete
// capability, which contributors lack, so the caller only reports its error.
func DiscardFailedUpload(client *api.Client, nodeID, versionID string, newNode bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if newNode {
		return client.DeleteDataroomNode(ctx, nodeID)
	}

	return client.DeleteDataroomNodeVersion(ctx, versionID)
}

// AddVersionToNode creates a new version on a node that is already known to
// exist, and returns the same descriptor as InitStreamUploadInto.
//
// Overwriting a file otherwise costs two extra round-trips: CreateDataroomNode
// answers 409, and locating the existing node then runs an uncached listing of
// the folder. A caller that already knows the node ID — the WebDAV server finds
// it in the parent's cached listing — skips both.
//
// NewNode is false: the node predates this upload, so a failed upload must not
// delete it, and its earlier versions must be preserved.
//
// The caller is responsible for the staleness of its node ID. The API answers
// 404, or 410 while its purge is pending (both match api.ErrNotFound), when the
// node is gone, which callers should treat as a signal to fall back to the full
// InitStreamUploadInto path.
func AddVersionToNode(
	ctx context.Context,
	client *api.Client,
	nodeID, fileName string,
	totalSize int64,
	sess *DataroomSession,
) (StreamUploadInit, error) {
	return addVersionToNode(ctx, client, dataroomIDUnknown, nodeID, fileName, totalSize, nil, sess)
}

// AddVersionToNodeIn is AddVersionToNode for a caller that knows the
// dataroom: the session can then load the dataroom's MIME table if it has
// not yet, instead of falling back to the legacy per-node ciphertext.
func AddVersionToNodeIn(
	ctx context.Context, client *api.Client, dataroomID, nodeID, fileName string, totalSize int64, sess *DataroomSession,
) (StreamUploadInit, error) {
	return addVersionToNode(ctx, client, dataroomID, nodeID, fileName, totalSize, nil, sess)
}

// dataroomIDUnknown marks a call that has no dataroom ID at hand for the MIME
// table (AddVersionToNode's route is keyed by node only): the session then
// uses the table it already loaded, if any, and the legacy ciphertext
// otherwise.
const dataroomIDUnknown = ""

// addVersionToNode is AddVersionToNode with the source's modification time.
func addVersionToNode(
	ctx context.Context, client *api.Client, dataroomID, nodeID, fileName string,
	totalSize int64, mtime *time.Time, sess *DataroomSession,
) (StreamUploadInit, error) {
	mimeType := guessMIMEType(fileName)
	var version *api.DataroomNodeVersion
	err := sess.withMIME(ctx, client, dataroomID, mimeType, func(m api.NodeMIME) (*api.DataroomNode, error) {
		var err error
		version, err = client.CreateDataroomNodeVersion(ctx, nodeID, api.VersionCreate{
			OriginalSize: totalSize, ChunkCount: ChunkCount(totalSize), MIME: m, ClientMtime: mtime,
		})

		return nil, err
	})
	if err != nil {
		return StreamUploadInit{}, fmt.Errorf("creating node version: %w", err)
	}

	return StreamUploadInit{
		NodeID:    nodeID,
		VersionID: version.ID,
		MIMEType:  mimeType,
		CreatedAt: version.CreatedAt,
		NewNode:   false,
	}, nil
}

// UploadSmallFile uploads a file that fits in one chunk (len(data) at most
// UploadChunkSize, nil or empty for an empty file) in a single request: the
// node, its version and the content together, instead of three round trips
// that each wait for the previous one's ID. A file already holding the name
// gets the upload as its next version. parentID is nil for the dataroom root.
//
// It returns the node as a listing would report it, and whether this upload
// created it. The server discards what a failed request created, so there is
// nothing for the caller to clean up.
func UploadSmallFile(
	ctx context.Context, client *api.Client, dataroomID string, parentID *string,
	fileName string, data []byte, sess *DataroomSession,
) (node DataroomNodeInfo, newNode bool, err error) {
	return uploadSmallFile(ctx, client, dataroomID, parentID, fileName, data, nil, sess)
}

// uploadSmallFile is UploadSmallFile with the source's modification time,
// declared to the API when known.
func uploadSmallFile(
	ctx context.Context, client *api.Client, dataroomID string, parentID *string,
	fileName string, data []byte, mtime *time.Time, sess *DataroomSession,
) (node DataroomNodeInfo, newNode bool, err error) {
	if len(data) > UploadChunkSize {
		return DataroomNodeInfo{}, false, fmt.Errorf(
			"%d bytes do not fit in a single %d-byte chunk", len(data), UploadChunkSize)
	}
	mimeType := guessMIMEType(fileName)
	nameEnc, err := crypto.EncryptStringForKeys(fileName, []string{sess.PublicKey})
	if err != nil {
		return DataroomNodeInfo{}, false, fmt.Errorf("encrypting filename: %w", err)
	}
	var chunk []byte
	if len(data) > 0 {
		if chunk, err = encryptChunk(ctx, 0, data, sess.PublicKey); err != nil {
			return DataroomNodeInfo{}, false, fmt.Errorf("encrypting chunk 0: %w", err)
		}
	}

	var item *api.DataroomNodeItem
	err = sess.withMIME(ctx, client, dataroomID, mimeType, func(m api.NodeMIME) (*api.DataroomNode, error) {
		var err error
		item, err = client.CreateDataroomFileNode(ctx, dataroomID, api.FileNodeCreate{
			ParentID: parentID, NameEnc: nameEnc, NameHash: nodeNameHash(fileName, sess.NameSalt), MIME: m,
			OriginalSize: int64(len(data)), Overwrite: true, ClientMtime: mtime, Chunk: chunk,
		})
		if err != nil {
			return nil, err
		}

		return &item.Node, nil
	})
	switch {
	case errors.Is(err, api.ErrGone):
		// 410: the name is held by a node pending deletion — not a missing
		// parent, which is a plain 404.
		return DataroomNodeInfo{}, false, fmt.Errorf("%q: %w", fileName, ErrNameBeingDeleted)
	case isConflict(err):
		return DataroomNodeInfo{}, false, fmt.Errorf(
			"cannot upload file %q: a folder holds the name, or it was taken concurrently: %w", fileName, err)
	case err != nil:
		return DataroomNodeInfo{}, false, fmt.Errorf("creating file: %w", err)
	case item.Version == nil:
		return DataroomNodeInfo{}, false, fmt.Errorf("creating file %q: the API returned no version", fileName)
	}

	info := DataroomNodeInfo{
		ID:         item.Node.ID,
		Name:       fileName,
		Type:       "file",
		MIMEType:   mimeType,
		Size:       int64(len(data)),
		VersionID:  item.Version.ID,
		ChunkCount: ChunkCount(int64(len(data))),
	}.WithModTime(item.Version.ModTime())
	if mode, ok := api.ParseAccessMode(item.Node.AccessMode); ok {
		info.mode = mode
	}

	return info, item.Version.VersionNumber <= 1, nil
}

// InitStreamUploadInto is InitStreamUpload with the parent directory already
// resolved to its node ID (nil for the dataroom root).
//
// resolvePath walks the tree with one uncached API listing per path level, on
// every single upload. A caller that already knows the parent — the WebDAV
// server holds it in its node cache — skips those round-trips entirely, which
// dominates upload latency against a remote API.
//
// It also returns the MIME type it derived, so a caller refreshing a cached
// listing entry does not have to recompute it and risk diverging from what was
// actually stored.
func InitStreamUploadInto(
	ctx context.Context,
	client *api.Client,
	dataroomID string,
	parentID *string,
	fileName string,
	totalSize int64,
	sess *DataroomSession,
) (StreamUploadInit, error) {
	return initStreamUploadInto(ctx, client, dataroomID, parentID, fileName, totalSize, nil, sess)
}

// initStreamUploadInto is InitStreamUploadInto with the source's modification
// time, declared to the API when known.
func initStreamUploadInto(
	ctx context.Context, client *api.Client, dataroomID string, parentID *string,
	fileName string, totalSize int64, mtime *time.Time, sess *DataroomSession,
) (StreamUploadInit, error) {
	mimeType := guessMIMEType(fileName)
	nameEnc, err := crypto.EncryptStringForKeys(fileName, []string{sess.PublicKey})
	if err != nil {
		return StreamUploadInit{}, fmt.Errorf("encrypting filename: %w", err)
	}

	var node *api.DataroomNode
	createErr := sess.withMIME(ctx, client, dataroomID, mimeType, func(m api.NodeMIME) (*api.DataroomNode, error) {
		var err error
		node, err = client.CreateDataroomNode(ctx, dataroomID, api.NodeCreate{
			ParentID: parentID, NameEnc: nameEnc, NameHash: nodeNameHash(fileName, sess.NameSalt), MIME: m,
		})

		return node, err
	})
	var targetNodeID string
	isNewNode := createErr == nil

	if createErr != nil {
		if !isConflict(createErr) {
			return StreamUploadInit{}, fmt.Errorf("creating file node: %w", createErr)
		}
		existingID, isFile, findErr := findNodeAndTypeByName(ctx, client, dataroomID, parentID, fileName, sess)
		if errors.Is(findErr, ErrNameBeingDeleted) {
			return StreamUploadInit{}, findErr
		}
		if findErr != nil {
			return StreamUploadInit{}, fmt.Errorf("node already exists but could not be located: %w", findErr)
		}
		if !isFile {
			return StreamUploadInit{}, fmt.Errorf("cannot upload file %q: a folder with that name already exists", fileName)
		}
		targetNodeID = existingID
	} else {
		targetNodeID = node.ID
	}

	init, err := addVersionToNode(ctx, client, dataroomID, targetNodeID, fileName, totalSize, mtime, sess)
	if err != nil {
		// A node created here without any version would linger as an empty,
		// undownloadable entry.
		if isNewNode {
			_ = DiscardFailedUpload(client, targetNodeID, "", true)
		}

		return StreamUploadInit{}, err
	}
	init.NewNode = isNewNode

	return init, nil
}

// uploadDataroomFile creates a file node (or adds a new version on 409) and uploads chunks.
func uploadDataroomFile(
	ctx context.Context, client *api.Client, dataroomID, filePath string,
	parentID *string, sess *DataroomSession, displayName string, progress ProgressFn,
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
	mtime := info.ModTime()
	if info.Size() <= UploadChunkSize {
		return uploadSmallDataroomFile(ctx, client, dataroomID, f, info.Size(), parentID, sess,
			name, displayName, &mtime, progress)
	}

	init, err := initStreamUploadInto(ctx, client, dataroomID, parentID, name, info.Size(), &mtime, sess)
	if err != nil {
		return err
	}
	if !init.NewNode {
		fmt.Fprintf(os.Stderr, "  %s: adding new version\n", displayName)
	}

	uploadErr := UploadChunks(ctx, f, info.Size(), displayName, sess.PublicKey, progress,
		func(ctx context.Context, chunkID int, data []byte) error {
			return client.UploadDataroomChunk(ctx, init.VersionID, chunkID, data)
		})
	if uploadErr != nil {
		if delErr := DiscardFailedUpload(client, init.NodeID, init.VersionID, init.NewNode); delErr == nil {
			fmt.Fprintf(os.Stderr, "  cleaned up: %s\n", displayName)
		} else {
			fmt.Fprintf(os.Stderr, "  %s: could not clean up the failed upload: %v\n", displayName, delErr)
		}
	}

	return uploadErr
}

// uploadSmallDataroomFile sends a local file that fits in one chunk through
// uploadSmallFile. The file must yield exactly size bytes, as for UploadChunks.
func uploadSmallDataroomFile(
	ctx context.Context, client *api.Client, dataroomID string, f io.Reader, size int64,
	parentID *string, sess *DataroomSession, name, displayName string, mtime *time.Time, progress ProgressFn,
) error {
	data, err := io.ReadAll(io.LimitReader(f, size+1))
	switch {
	case err != nil:
		return fmt.Errorf("reading file: %w", err)
	case int64(len(data)) > size:
		return fmt.Errorf("source is larger than its declared %d bytes", size)
	case int64(len(data)) < size:
		return fmt.Errorf("source ended after %d of its declared %d bytes", len(data), size)
	}
	_, newNode, err := uploadSmallFile(ctx, client, dataroomID, parentID, name, data, mtime, sess)
	if err != nil {
		return err
	}
	if !newNode {
		fmt.Fprintf(os.Stderr, "  %s: added as a new version\n", displayName)
	}
	if progress != nil && size > 0 {
		progress(displayName, int(size), size)
	}

	return nil
}

type dirQueueEntry struct {
	localPath    string
	remoteParent *string
	relPath      string
}

// uploadDataroomDir recursively uploads a local directory into the dataroom using BFS.
func uploadDataroomDir(
	ctx context.Context, client *api.Client, dataroomID, localDir string,
	parentID *string, sess *DataroomSession, progress ProgressFn,
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
				folderID, err := ensureFolder(ctx, client, dataroomID, entry.remoteParent, e.Name(), sess)
				if err != nil {
					return err
				}
				queue = append(queue, dirQueueEntry{localPath: fullPath, remoteParent: &folderID, relPath: relPath})
			} else {
				if err := uploadDataroomFile(
					ctx, client, dataroomID, fullPath, entry.remoteParent, sess, relPath, progress,
				); err != nil {
					return fmt.Errorf("%s: %w", relPath, err)
				}
			}
		}
	}

	return nil
}

// ensureFolder creates the folder name under parentID, or returns the ID of
// the existing folder of that name.
func ensureFolder(
	ctx context.Context, client *api.Client, dataroomID string, parentID *string, name string, sess *DataroomSession,
) (string, error) {
	nameEnc, err := crypto.EncryptStringForKeys(name, []string{sess.PublicKey})
	if err != nil {
		return "", fmt.Errorf("encrypting dir name: %w", err)
	}
	node, createErr := client.CreateDataroomNode(ctx, dataroomID, api.NodeCreate{
		ParentID: parentID, NameEnc: nameEnc, NameHash: nodeNameHash(name, sess.NameSalt), Folder: true,
	})
	if createErr == nil {
		return node.ID, nil
	}
	if !isConflict(createErr) {
		return "", fmt.Errorf("creating folder %s: %w", name, createErr)
	}
	existingID, isFile, findErr := findNodeAndTypeByName(ctx, client, dataroomID, parentID, name, sess)
	if errors.Is(findErr, ErrNameBeingDeleted) {
		return "", findErr
	}
	if findErr != nil {
		return "", fmt.Errorf("folder %s already exists but could not be located: %w", name, findErr)
	}
	if isFile {
		return "", fmt.Errorf("cannot create folder %q: a file with that name already exists", name)
	}

	return existingID, nil
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
	destParentID, err := resolvePathWithSession(ctx, client, dataroomID, dstPath, sess)
	if err != nil {
		return err
	}

	for _, localPath := range localPaths {
		info, err := os.Stat(localPath)
		if err != nil {
			return err
		}
		if info.IsDir() {
			if err := uploadDataroomDir(ctx, client, dataroomID, localPath, destParentID, sess, progress); err != nil {
				return fmt.Errorf("%s: %w", info.Name(), err)
			}
		} else {
			if err := uploadDataroomFile(ctx, client, dataroomID, localPath, destParentID, sess, "", progress); err != nil {
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
		files := make([]api.DataroomNodeItem, 0, len(matches))
		names := make([]string, 0, len(matches))
		for _, item := range matches {
			if item.Node.IsFolder() || item.Version == nil {
				continue
			}
			name, decErr := crypto.DecryptToString(item.Node.NameEnc, sess.Identity)
			if decErr != nil {
				name = item.Node.ID
			}
			files = append(files, item)
			names = append(names, name)
		}
		// Map every name before downloading anything: two matches may share
		// a local name once sanitized.
		localNames := localFileNames(names)
		for i, item := range files {
			name, local := names[i], localNames[i]
			if err := downloadVersion(ctx, client, outputDir, local, item.Version, sess, progress); err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			downloaded = append(downloaded, filepath.Join(outputDir, local))
		}

		return downloaded, nil
	}

	item, err := resolvePathItemWithSession(ctx, client, src.DataroomID, src.Path, sess)
	if err != nil {
		return nil, err
	}
	if item == nil {
		return nil, fmt.Errorf("cannot download the root folder")
	}
	if item.Node.IsFolder() {
		return nil, fmt.Errorf("%s is a folder — use `ls` to browse it", src.Path)
	}
	if item.Version == nil {
		return nil, fmt.Errorf("node has no version yet")
	}

	name, err := crypto.DecryptToString(item.Node.NameEnc, sess.Identity)
	if err != nil {
		name = item.Node.ID
	}

	local := localFileName(name)
	if err := downloadVersion(ctx, client, outputDir, local, item.Version, sess, progress); err != nil {
		return nil, err
	}

	downloaded = append(downloaded, filepath.Join(outputDir, local))

	return downloaded, nil
}

// downloadVersion downloads version into outputDir/localName and gives the
// file the modification time the uploader declared, when it declared one.
// A failure to set the time is not an error: the content is there.
func downloadVersion(
	ctx context.Context, client *api.Client, outputDir, localName string,
	version *api.DataroomNodeVersion, sess *DataroomSession, progress ProgressFn,
) error {
	if err := DownloadChunks(
		ctx, outputDir, localName,
		version.OriginalSize, version.ChunkCount, sess.Identity, progress,
		func(ctx context.Context, chunkID int) ([]byte, error) {
			return client.DownloadDataroomChunk(ctx, version.ID, chunkID)
		},
	); err != nil {
		return err
	}
	if version.ClientMtime != nil {
		_ = os.Chtimes(filepath.Join(outputDir, localName), *version.ClientMtime, *version.ClientMtime)
	}

	return nil
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

	parentID, err := resolvePathWithSession(ctx, client, dataroomID, parentPath, sess)
	if err != nil {
		return "", err
	}

	return MkdirDataroomInto(ctx, client, dataroomID, parentID, name, sess)
}

// MkdirDataroomInto creates the folder name under parentID (nil for the
// dataroom root) and returns its node ID, for callers that already know the
// parent's ID — the WebDAV server reads it from its cached listings instead of
// walking the path from the root.
func MkdirDataroomInto(
	ctx context.Context, client *api.Client, dataroomID string, parentID *string, name string, sess *DataroomSession,
) (string, error) {
	nameEnc, err := crypto.EncryptStringForKeys(name, []string{sess.PublicKey})
	if err != nil {
		return "", fmt.Errorf("encrypting folder name: %w", err)
	}

	node, err := client.CreateDataroomNode(ctx, dataroomID, api.NodeCreate{
		ParentID: parentID, NameEnc: nameEnc, NameHash: nodeNameHash(name, sess.NameSalt), Folder: true,
	})
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

	return DeleteDataroomNodeLiteralWithSession(ctx, client, dataroomID, nodePath, sess)
}

// DeleteDataroomNodeLiteralWithSession deletes the single node at nodePath,
// resolving every path component by its exact name (no glob interpretation).
// WebDAV relays client-supplied paths through it: a file named
// "notes[draft].txt" must delete itself, never a sibling matching the class.
func DeleteDataroomNodeLiteralWithSession(
	ctx context.Context, client *api.Client, dataroomID, nodePath string, sess *DataroomSession,
) (int, error) {
	nodeID, err := resolvePathWithSession(ctx, client, dataroomID, nodePath, sess)
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
	srcNodeID, err := resolvePathWithSession(ctx, client, dataroomID, srcPath, sess)
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

	dstParentID, err := resolvePathWithSession(ctx, client, dataroomID, dstParentPath, sess)
	if err != nil {
		return err
	}

	return MoveDataroomNodeByID(ctx, client, *srcNodeID, dstParentID, newName, sess)
}

// MoveDataroomNodeByID renames node nodeID to newName under dstParentID (nil for
// the dataroom root), for callers that already know both IDs and so need no
// path resolution.
func MoveDataroomNodeByID(
	ctx context.Context, client *api.Client, nodeID string, dstParentID *string, newName string, sess *DataroomSession,
) error {
	nameEnc, err := crypto.EncryptStringForKeys(newName, []string{sess.PublicKey})
	if err != nil {
		return fmt.Errorf("encrypting new name: %w", err)
	}

	if err := client.RenameDataroomNode(
		ctx, nodeID, nameEnc, nodeNameHash(newName, sess.NameSalt), dstParentID,
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

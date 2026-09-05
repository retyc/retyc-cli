package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/crypto"
)

// ErrOrgKeyNoAccess means the organization key cannot decrypt the session key:
// the dataroom or transfer was never rekeyed for the organization.
var ErrOrgKeyNoAccess = errors.New(
	"the organization key cannot open this content (it was never rekeyed for the organization)")

// ResolveAdminDataroomSession fetches a dataroom through the admin API and
// decrypts its session key with the organization identity.
// NameSalt stays empty: the admin API exposes no salt and admin commands never
// compute a name_hash (they are read-only on nodes).
func ResolveAdminDataroomSession(
	ctx context.Context, client *api.Client, orgKey *age.HybridIdentity, dataroomID string,
) (*DataroomSession, error) {
	dr, err := client.AdminGetDataroom(ctx, dataroomID)
	if err != nil {
		return nil, fmt.Errorf("fetching dataroom: %w", err)
	}

	sessionPrivKey, err := crypto.DecryptToString(dr.SessionPrivateKeyEnc, orgKey)
	if err != nil {
		return nil, ErrOrgKeyNoAccess
	}

	sessionIdentity, err := crypto.ParseIdentity(sessionPrivKey)
	if err != nil {
		return nil, fmt.Errorf("parsing session AGE identity: %w", err)
	}

	return &DataroomSession{
		Identity:   sessionIdentity,
		PublicKey:  dr.SessionPublicKey,
		PrivateKey: sessionPrivKey,
	}, nil
}

// AdminNodeInfo is a dataroom node with its decrypted name and full path.
type AdminNodeInfo struct {
	ID            string
	Path          string
	Name          string
	IsFolder      bool
	Size          int64
	ChunkCount    int
	VersionNumber int
	HasContent    bool
}

// sanitizeNodeName neutralizes a decrypted node name before it is used to
// build an on-disk or display path. The dataroom owner controls node names
// (they are encrypted client-side, never validated by the server), so a
// malicious name like "../evil.sh" or one embedding "/" must not be able to
// escape the directory it is joined into. Both the displayed Path and the
// on-disk write path use the sanitized name: the raw decrypted name is never
// trusted for filesystem layout.
func sanitizeNodeName(name string) string {
	switch name {
	case "", ".", "..":
		return "_"
	}

	sanitized := strings.NewReplacer("/", "_", "\\", "_").Replace(name)
	// Replacing separators alone can still leave a literal ".." behind, e.g.
	// "../evil.sh" becomes ".._evil.sh": strip it too so the sanitized name
	// can never reconstitute a directory-traversal segment once joined.
	sanitized = strings.ReplaceAll(sanitized, "..", "__")

	return sanitized
}

// uniqueSiblingName returns name, or "stem (n).ext" for the smallest n >= 2
// that is not already taken under parentKey, and marks the result as taken.
func uniqueSiblingName(taken map[string]bool, parentKey, name string) string {
	key := parentKey + "/" + name
	if !taken[key] {
		taken[key] = true

		return name
	}
	ext := path.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	for n := 2; ; n++ {
		candidate := fmt.Sprintf("%s (%d)%s", stem, n, ext)
		if key := parentKey + "/" + candidate; !taken[key] {
			taken[key] = true

			return candidate
		}
	}
}

// buildAdminNodeTree decrypts node names and computes each node's full path
// from the flat parent_id listing. A node whose parent is missing from the
// listing is rooted at "/": the admin view must never silently drop content.
func buildAdminNodeTree(nodes []api.AdminDataroomNode, sessionID age.Identity) ([]AdminNodeInfo, error) {
	names := make(map[string]string, len(nodes))
	parents := make(map[string]*string, len(nodes))
	// Sanitizing is many-to-one ("q1/report.pdf" and "q1_report.pdf" both
	// sanitize to "q1_report.pdf"), so siblings may collide once sanitized.
	// Give later siblings a " (n)" suffix, in listing order, so every node
	// keeps a distinct on-disk path instead of tripping the file-exists guard.
	// A node whose parent is missing from the listing is rooted at "/" by
	// nodePath below, so it competes with the root-level names: key it as a
	// root node, not by its (dangling) parent ID.
	known := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		known[n.ID] = true
	}
	taken := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		name, err := crypto.DecryptToString(n.NameEnc, sessionID)
		if err != nil {
			return nil, fmt.Errorf("decrypting name of node %s: %w", n.ID, err)
		}
		parentKey := ""
		if n.ParentID != nil && known[*n.ParentID] {
			parentKey = *n.ParentID
		}
		names[n.ID] = uniqueSiblingName(taken, parentKey, sanitizeNodeName(name))
		parents[n.ID] = n.ParentID
	}

	// nodePath resolves the full path of a node, walking up the parent chain.
	var nodePath func(id string, depth int) string
	nodePath = func(id string, depth int) string {
		// depth guards against a parent_id cycle in corrupted data.
		if depth > len(nodes) {
			return "/" + names[id]
		}
		p := parents[id]
		if p == nil {
			return "/" + names[id]
		}
		if _, ok := names[*p]; !ok {
			return "/" + names[id]
		}

		return path.Join(nodePath(*p, depth+1), names[id])
	}

	infos := make([]AdminNodeInfo, 0, len(nodes))
	for _, n := range nodes {
		info := AdminNodeInfo{
			ID:       n.ID,
			Path:     nodePath(n.ID, 0),
			Name:     names[n.ID],
			IsFolder: n.IsFolder,
		}
		if n.OriginalSize != nil {
			info.Size = *n.OriginalSize
		}
		if n.ChunkCount != nil {
			info.ChunkCount = *n.ChunkCount
		}
		if n.VersionNumber != nil {
			info.VersionNumber = *n.VersionNumber
		}
		info.HasContent = !n.IsFolder && n.VersionID != nil
		infos = append(infos, info)
	}

	return infos, nil
}

// AdminListNodes returns every node of a dataroom with decrypted names and
// full paths, fetching all pages of the flat admin listing.
func AdminListNodes(
	ctx context.Context, client *api.Client, orgKey *age.HybridIdentity, dataroomID string,
) ([]AdminNodeInfo, error) {
	sess, err := ResolveAdminDataroomSession(ctx, client, orgKey, dataroomID)
	if err != nil {
		return nil, err
	}

	nodes, err := api.GetAllAdminPages[api.AdminDataroomNode](ctx, client, func(page int) string {
		return fmt.Sprintf("/dataroom/%s/nodes?page=%d&size=100", dataroomID, page)
	})
	if err != nil {
		return nil, fmt.Errorf("listing nodes: %w", err)
	}

	return buildAdminNodeTree(nodes, sess.Identity)
}

// matchAdminNodes selects the file nodes matching pattern (a path glob, or
// every file when empty). Matching folders are reported in skippedFolders:
// the admin download is flat, it does not recurse into folders. Files without
// downloadable content are ignored.
func matchAdminNodes(
	nodes []AdminNodeInfo, pattern string,
) (files []AdminNodeInfo, skippedFolders []string, err error) {
	if pattern != "" && !strings.HasPrefix(pattern, "/") {
		pattern = "/" + pattern
	}
	matched := false
	for _, n := range nodes {
		if pattern != "" {
			ok, matchErr := path.Match(pattern, n.Path)
			if matchErr != nil {
				return nil, nil, fmt.Errorf("invalid glob pattern %q: %w", pattern, matchErr)
			}
			if !ok {
				continue
			}
		}
		matched = true
		if n.IsFolder {
			if pattern != "" {
				skippedFolders = append(skippedFolders, n.Path)
			}

			continue
		}
		if !n.HasContent {
			continue
		}
		files = append(files, n)
	}
	if pattern != "" && !matched {
		return nil, nil, fmt.Errorf("no node matches %q", pattern)
	}

	return files, skippedFolders, nil
}

// AdminDownloadResult summarizes an admin dataroom download.
type AdminDownloadResult struct {
	Downloaded     []string
	SkippedFolders []string
	// SkippedExisting lists files (relative paths) left untouched because a
	// file already existed at their destination.
	SkippedExisting []string
}

// AdminDownloadNodes downloads and decrypts the file nodes of a dataroom
// matching pattern into outputDir, using the organization key. The
// dataroom's folder structure is recreated under outputDir (each file is
// written at its relative path) so that files with the same name in
// different folders never collide.
func AdminDownloadNodes(
	ctx context.Context, client *api.Client, orgKey *age.HybridIdentity,
	dataroomID, pattern, outputDir string, progress ProgressFn,
) (*AdminDownloadResult, error) {
	sess, err := ResolveAdminDataroomSession(ctx, client, orgKey, dataroomID)
	if err != nil {
		return nil, err
	}

	nodes, err := api.GetAllAdminPages[api.AdminDataroomNode](ctx, client, func(page int) string {
		return fmt.Sprintf("/dataroom/%s/nodes?page=%d&size=100", dataroomID, page)
	})
	if err != nil {
		return nil, fmt.Errorf("listing nodes: %w", err)
	}
	infos, err := buildAdminNodeTree(nodes, sess.Identity)
	if err != nil {
		return nil, err
	}

	files, skippedFolders, err := matchAdminNodes(infos, pattern)
	if err != nil {
		return nil, err
	}

	absOutputDir, err := filepath.Abs(outputDir)
	if err != nil {
		return nil, fmt.Errorf("resolving output directory: %w", err)
	}
	// Root-level files are written directly into outputDir: make sure it
	// exists even when no subfolder creation would have brought it along.
	if err := os.MkdirAll(outputDir, 0o750); err != nil {
		return nil, fmt.Errorf("creating output directory: %w", err)
	}

	result := &AdminDownloadResult{SkippedFolders: skippedFolders}
	for _, f := range files {
		nodeID := f.ID
		relDir := path.Dir(strings.TrimPrefix(f.Path, "/"))
		relPath := f.Name
		fileOutputDir := outputDir
		if relDir != "." {
			fileOutputDir = filepath.Join(outputDir, relDir)
			relPath = filepath.Join(relDir, f.Name)
		}

		// Defense in depth on top of sanitizeNodeName: verify the resolved
		// directory never escapes outputDir before writing anything to disk.
		absFileOutputDir, err := filepath.Abs(fileOutputDir)
		if err != nil {
			return nil, fmt.Errorf("resolving output directory for %s: %w", f.Path, err)
		}
		if absFileOutputDir != absOutputDir &&
			!strings.HasPrefix(absFileOutputDir, absOutputDir+string(filepath.Separator)) {
			return nil, fmt.Errorf("refusing to write %s outside of output directory", f.Path)
		}

		if relDir != "." {
			if err := os.MkdirAll(fileOutputDir, 0o750); err != nil {
				return nil, fmt.Errorf("creating directory for %s: %w", f.Path, err)
			}
		}

		err = DownloadChunks(ctx, fileOutputDir, f.Name, f.Size, f.ChunkCount, sess.Identity, progress,
			func(ctx context.Context, chunkID int) ([]byte, error) {
				return client.AdminDownloadNodeChunk(ctx, nodeID, chunkID)
			})
		if errors.Is(err, ErrFileExists) {
			// A re-run into a populated directory: keep going, report it.
			result.SkippedExisting = append(result.SkippedExisting, relPath)

			continue
		}
		if err != nil {
			return nil, fmt.Errorf("downloading %s: %w", f.Path, err)
		}
		result.Downloaded = append(result.Downloaded, relPath)
	}

	return result, nil
}

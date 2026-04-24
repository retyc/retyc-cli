package cmd

import (
	"bufio"
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"mime"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"text/tabwriter"
	"time"

	"filippo.io/age"
	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/config"
	"github.com/retyc/retyc-cli/internal/crypto"
	"github.com/retyc/retyc-cli/internal/ui"
	"github.com/spf13/cobra"
)

var dataroomCmd = &cobra.Command{
	Use:   "dataroom",
	Short: "Manage datarooms",
}

var dataroomUserCmd = &cobra.Command{
	Use:   "user",
	Short: "Manage dataroom users",
}

// — URI helpers ——————————————————————————————————————————————————————————————

// retycURI holds the parsed components of a retyc://dataroom_id/path URI.
type retycURI struct {
	dataroomID string
	path       string // always starts with /
}

// parseRetycURI parses a URI of the form retyc://dataroom_id[/path].
func parseRetycURI(s string) (*retycURI, error) {
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

	return &retycURI{dataroomID: drID, path: nodePath}, nil
}

// — Glob helpers —————————————————————————————————————————————————————————————

// hasGlob reports whether s contains any glob metacharacter.
func hasGlob(s string) bool {
	return strings.ContainsAny(s, "*?[")
}

// namedNode pairs a decrypted name with its API item.
type namedNode struct {
	name string
	item api.DataroomNodeItem
}

// fetchNodesWithNames lists all paginated nodes in a folder and decrypts their names.
func fetchNodesWithNames(
	ctx context.Context,
	client *api.Client,
	dataroomID string,
	parentID *string,
	identity *age.HybridIdentity,
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
				continue // skip nodes we cannot decrypt (wrong key or corruption)
			}
			result = append(result, namedNode{name: name, item: item})
		}
		if page >= p.Pages {
			break
		}
	}

	return result, nil
}

// resolveGlob resolves a path that may contain glob patterns in any component.
// It returns all DataroomNodeItem leaf nodes that match the full path pattern.
// Non-glob components are matched exactly; glob components are expanded against
// the actual node names at that level using path.Match syntax (* ? [...]).
func resolveGlob(
	ctx context.Context,
	client *api.Client,
	dataroomID, rawPath string,
	identity *age.HybridIdentity,
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

// — Crypto helpers ———————————————————————————————————————————————————————————

// nodeNameHash computes SHA-256(salt + name), where salt is the per-dataroom name salt
// (decrypted from node_name_salt_enc). Pass "" when the dataroom has no salt.
func nodeNameHash(name, salt string) string {
	h := sha256.Sum256([]byte(salt + name))

	return hex.EncodeToString(h[:])
}

// dataroomSession holds the decrypted session material for a dataroom.
type dataroomSession struct {
	Identity   *age.HybridIdentity
	PublicKey  string
	PrivateKey string
	// NameSalt is the per-dataroom salt prefix for node name hashing (from
	// node_name_salt_enc, decrypted with the session key). Empty string when not set.
	NameSalt string
}

// resolveDataroomSession fetches the dataroom and the user's active key concurrently,
// then prompts for the passphrase (or reads from keyring) and decrypts the session key
// and the per-dataroom name salt. The spinner is managed internally: it runs during API
// calls and is stopped before the passphrase prompt so the terminal is not overwritten.
func resolveDataroomSession(
	ctx context.Context,
	cfg *config.Config,
	client *api.Client,
	dataroomID string,
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

	s := ui.NewSpinner()
	s.Start()

	go func() { v, err := client.GetDataroom(ctx, dataroomID); drCh <- drResult{v, err} }()
	go func() { v, err := client.GetActiveKey(ctx); keyCh <- keyResult{v, err} }()

	dr := <-drCh
	kr := <-keyCh
	s.Stop() // must stop before any passphrase prompt

	if dr.err != nil {
		return nil, fmt.Errorf("fetching dataroom: %w", dr.err)
	}
	if kr.err != nil {
		return nil, fmt.Errorf("fetching encryption key: %w", kr.err)
	}
	if kr.v == nil {
		return nil, fmt.Errorf("no active encryption key - set up your key in the web interface first")
	}

	userIdentity, err := resolveUserIdentity(cfg, kr.v)
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

	// Decrypt the per-dataroom name salt if present.
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

// resolvePath resolves a unix-style path (e.g. "/Documents/report.pdf") to the node ID
// of the final component by decrypting names at each level.
// Returns nil for an empty path or "/", indicating the dataroom root.
func resolvePath(
	ctx context.Context,
	client *api.Client,
	dataroomID string,
	nodePath string,
	identity *age.HybridIdentity,
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
			built := "/" + strings.Join(parts[:depth+1], "/")

			return nil, fmt.Errorf("path not found: %s", built)
		}
	}

	return currentParentID, nil
}

// splitPathParent splits a path into its parent directory path and final component name.
// e.g. "/Documents/Reports" → ("/Documents", "Reports")
//
//	"/file.txt"          → ("/", "file.txt")
//	"file.txt"           → ("/", "file.txt")
func splitPathParent(path string) (parentPath, name string) {
	path = strings.TrimRight(path, "/")
	idx := strings.LastIndex(path, "/")
	if idx <= 0 {
		return "/", strings.TrimPrefix(path, "/")
	}

	return path[:idx], path[idx+1:]
}

// — Upload / download helpers ————————————————————————————————————————————————

// isConflict reports whether err is an API 409 Conflict response.
func isConflict(err error) bool {
	return err != nil && strings.Contains(err.Error(), "API error 409")
}

// findNodeByName scans a folder for a node whose decrypted name matches name.
func findNodeByName(
	ctx context.Context,
	client *api.Client,
	dataroomID string,
	parentID *string,
	name string,
	identity *age.HybridIdentity,
) (string, error) {
	nodes, err := fetchNodesWithNames(ctx, client, dataroomID, parentID, identity)
	if err != nil {
		return "", err
	}
	for _, nn := range nodes {
		if nn.name == name {
			return nn.item.Node.ID, nil
		}
	}

	return "", fmt.Errorf("node %q not found in folder", name)
}

// uploadDataroomFile creates a file node in the dataroom (or adds a new version
// if a node with the same name already exists), then uploads all encrypted chunks.
// displayName is shown in the progress bar; pass "" to use the base filename.
// It mirrors the transfer upload pattern.
//
//nolint:dupl
func uploadDataroomFile(
	ctx context.Context,
	client *api.Client,
	dataroomID, filePath string,
	parentID *string,
	sessionPubKey string,
	sessionIdentity *age.HybridIdentity,
	displayName string,
	nameSalt string,
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
	newNode := createErr == nil // true if we created this node (vs reusing an existing one on 409)
	if createErr != nil {
		if !isConflict(createErr) {
			return fmt.Errorf("creating file node: %w", createErr)
		}
		// 409: a node with this name already exists — add a new version only if it is a file.
		existingID, findErr := findNodeByName(ctx, client, dataroomID, parentID, name, sessionIdentity)
		if findErr != nil {
			return fmt.Errorf("node already exists but could not be located: %w", findErr)
		}
		existing, fetchErr := client.GetDataroomNode(ctx, existingID)
		if fetchErr != nil {
			return fmt.Errorf("verifying existing node %q: %w", name, fetchErr)
		}
		if existing.Node.TypeEnc == nil {
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

	uploadErr := uploadChunks(ctx, f, info.Size(), displayName, sessionPubKey,
		func(ctx context.Context, chunkID int, data []byte) error {
			return client.UploadDataroomChunk(ctx, version.ID, chunkID, data)
		})
	if uploadErr != nil && newNode {
		// Best-effort cleanup: delete the node we just created so it does not remain
		// orphaned with an incomplete version (applies to any error, not only SIGINT).
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		if delErr := client.DeleteDataroomNode(cleanupCtx, targetNodeID); delErr == nil {
			fmt.Fprintf(os.Stderr, "  cleaned up: %s\n", displayName)
		}
	}

	return uploadErr
}

type dirQueueEntry struct {
	localPath    string
	remoteParent *string
	relPath      string // relative path from upload root, used for progress display
}

// uploadDataroomDir recursively uploads a local directory into the dataroom using BFS.
func uploadDataroomDir(
	ctx context.Context,
	client *api.Client,
	dataroomID, localDir string,
	parentID *string,
	sessionPubKey string,
	sessionIdentity *age.HybridIdentity,
	nameSalt string,
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
					// 409: a node with this name exists — reuse it only if it is a directory.
					existingID, findErr := findNodeByName(ctx, client, dataroomID, entry.remoteParent, e.Name(), sessionIdentity)
					if findErr != nil {
						return fmt.Errorf("folder %s already exists but could not be located: %w", e.Name(), findErr)
					}
					// Fetch the node to verify it is actually a directory.
					existing, fetchErr := client.GetDataroomNode(ctx, existingID)
					if fetchErr != nil {
						return fmt.Errorf("verifying existing node %s: %w", e.Name(), fetchErr)
					}
					if existing.Node.TypeEnc != nil {
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
					sessionPubKey, sessionIdentity, relPath, nameSalt,
				); err != nil {
					return fmt.Errorf("%s: %w", relPath, err)
				}
			}
		}
	}

	return nil
}

// downloadDataroomFile downloads all chunks of a version in parallel, decrypts them,
// and writes them in order to outputDir/<name> via downloadChunks.
func downloadDataroomFile(
	ctx context.Context,
	client *api.Client,
	outputDir string,
	version *api.DataroomNodeVersion,
	name string,
	identity *age.HybridIdentity,
) error {
	return downloadChunks(ctx, outputDir, name, version.OriginalSize, version.ChunkCount, identity,
		func(ctx context.Context, chunkID int) ([]byte, error) {
			return client.DownloadDataroomChunk(ctx, version.ID, chunkID)
		})
}

// — dataroom ls ——————————————————————————————————————————————————————————————

var dataroomLsCmd = &cobra.Command{
	Use:   "ls [retyc://dataroom_id[/path]]",
	Short: "List datarooms, or list files in a dataroom path",
	Args:  cobra.RangeArgs(0, 1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		// No argument: list all datarooms.
		if len(args) == 0 {
			_, client, err := newAPIClient(ctx)
			if err != nil {
				return err
			}
			s := ui.NewSpinner()
			s.Start()
			result, err := client.ListDatarooms(ctx, 1)
			s.Stop()
			if err != nil {
				return fmt.Errorf("listing datarooms: %w", err)
			}
			if len(result.Items) == 0 {
				fmt.Println("No datarooms found.")

				return nil
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "DATAROOM ID\tTITLE\tCREATED")
			for _, dr := range result.Items {
				fmt.Fprintf(w, "%s\t%s\t%s\n",
					dr.ID,
					dr.Title,
					dr.CreatedAt.Format("2006-01-02 15:04"),
				)
			}
			_ = w.Flush()
			if result.Pages > 1 {
				fmt.Printf("\nPage 1/%d · %d dataroom(s) total\n", result.Pages, result.Total)
			}

			return nil
		}

		// retyc:// argument: list nodes.
		uri, err := parseRetycURI(args[0])
		if err != nil {
			return err
		}

		cfg, client, err := newAPIClient(ctx)
		if err != nil {
			return err
		}

		sess, err := resolveDataroomSession(ctx, cfg, client, uri.dataroomID)
		if err != nil {
			return err
		}

		s := ui.NewSpinner()
		s.Start()

		var items []api.DataroomNodeItem
		if hasGlob(uri.path) {
			// Glob mode: expand pattern and collect matching nodes.
			items, err = resolveGlob(ctx, client, uri.dataroomID, uri.path, sess.Identity)
		} else {
			// Exact mode: list children of the resolved folder.
			var parentID *string
			parentID, err = resolvePath(ctx, client, uri.dataroomID, uri.path, sess.Identity)
			if err == nil {
				for page := 1; ; page++ {
					var p *api.DataroomNodePage
					p, err = client.ListDataroomNodes(ctx, uri.dataroomID, parentID, page, 50)
					if err != nil {
						break
					}
					items = append(items, p.Items...)
					if page >= p.Pages {
						break
					}
				}
			}
		}
		s.Stop()
		if err != nil {
			return err
		}

		if len(items) == 0 {
			fmt.Println("No matching nodes.")

			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "TYPE\tNAME\tSIZE")
		for _, item := range items {
			name, decErr := crypto.DecryptToString(item.Node.NameEnc, sess.Identity)
			if decErr != nil {
				name = "(encrypted)"
			}
			if item.Node.TypeEnc == nil {
				fmt.Fprintf(w, "DIR\t%s\t\n", name)
			} else {
				size := ""
				if item.Version != nil {
					size = ui.FormatSize(item.Version.OriginalSize)
				}
				fmt.Fprintf(w, "FILE\t%s\t%s\n", name, size)
			}
		}
		_ = w.Flush()

		return nil
	},
}

// — dataroom create ——————————————————————————————————————————————————————————

var dataroomCreateCmd = &cobra.Command{
	Use:   "create --title <title>",
	Short: "Create a new dataroom",
	RunE: func(cmd *cobra.Command, args []string) error {
		title, _ := cmd.Flags().GetString("title")

		ctx := cmd.Context()
		_, client, err := newAPIClient(ctx)
		if err != nil {
			return err
		}

		s := ui.NewSpinner()
		s.Start()
		s.SetLabel("Fetching encryption key")
		userKey, err := client.GetActiveKey(ctx)
		if err != nil {
			s.Stop()

			return fmt.Errorf("fetching encryption key: %w", err)
		}
		if userKey == nil {
			s.Stop()

			return fmt.Errorf("no active encryption key - set up your key in the web interface first")
		}
		s.SetLabel("Generating session key")
		sessionIdentity, err := crypto.GenerateKeyPair()
		if err != nil {
			s.Stop()

			return fmt.Errorf("generating session key: %w", err)
		}
		sessionPrivKey := sessionIdentity.String()
		sessionPubKey := sessionIdentity.Recipient().String()

		sessionPrivKeyEnc, err := crypto.EncryptStringForKeys(sessionPrivKey, []string{userKey.PublicKey})
		if err != nil {
			s.Stop()

			return fmt.Errorf("encrypting session key: %w", err)
		}

		// Generate a random per-dataroom salt and encrypt it for future name hashing.
		saltBytes := make([]byte, 16)
		if _, err := cryptorand.Read(saltBytes); err != nil {
			s.Stop()

			return fmt.Errorf("generating name salt: %w", err)
		}
		nameSalt := hex.EncodeToString(saltBytes)
		nameSaltEnc, err := crypto.EncryptStringForKeys(nameSalt, []string{sessionPubKey})
		if err != nil {
			s.Stop()

			return fmt.Errorf("encrypting name salt: %w", err)
		}

		s.SetLabel("Creating dataroom")
		dr, err := client.CreateDataroom(ctx, title, sessionPrivKeyEnc, sessionPubKey, &nameSaltEnc)
		s.Stop()
		if err != nil {
			return fmt.Errorf("creating dataroom: %w", err)
		}

		fmt.Printf("Dataroom %s created.\n", dr.ID)
		if dr.Title != "" {
			fmt.Printf("Title: %s\n", dr.Title)
		}

		return nil
	},
}

// — dataroom info ————————————————————————————————————————————————————————————

var dataroomInfoCmd = &cobra.Command{
	Use:   "info <dataroom_id>",
	Short: "Show dataroom details, stats and members",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		drID := args[0]

		ctx := cmd.Context()
		_, client, err := newAPIClient(ctx)
		if err != nil {
			return err
		}

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

		s := ui.NewSpinner()
		s.Start()

		go func() { v, err := client.GetDataroom(ctx, drID); drCh <- drResult{v, err} }()
		go func() { v, err := client.GetDataroomStats(ctx, drID); statsCh <- statsResult{v, err} }()
		go func() { v, err := client.GetDataroomUsers(ctx, drID); usersCh <- usersResult{v, err} }()

		dr := <-drCh
		stats := <-statsCh
		users := <-usersCh
		s.Stop()

		if dr.err != nil {
			return fmt.Errorf("fetching dataroom: %w", dr.err)
		}
		if stats.err != nil {
			return fmt.Errorf("fetching stats: %w", stats.err)
		}
		if users.err != nil {
			return fmt.Errorf("fetching users: %w", users.err)
		}

		fmt.Printf("ID:      %s\n", dr.v.ID)
		fmt.Printf("Title:   %s\n", dr.v.Title)
		fmt.Printf("Created: %s\n", dr.v.CreatedAt.Format("2006-01-02 15:04"))

		if stats.v != nil {
			fmt.Printf("\nFiles:   %d · %s (encrypted)\n", stats.v.FilesCount, ui.FormatSize(stats.v.FilesEncryptedSize))
		}

		if len(users.v) > 0 {
			fmt.Println("\nUsers:")
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "  EMAIL\tROLE\tUSER ID")
			for _, u := range users.v {
				fmt.Fprintf(w, "  %s\t%s\t%s\n", u.UserEmail, u.Role, u.UserID)
			}
			_ = w.Flush()
		}

		return nil
	},
}

// — dataroom user add ————————————————————————————————————————————————————————

var dataroomUserAddCmd = &cobra.Command{
	Use:   "add <dataroom_id> <email>",
	Short: "Add a user to a dataroom",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		drID := args[0]
		email := args[1]
		role, _ := cmd.Flags().GetString("role")

		ctx := cmd.Context()
		cfg, client, err := newAPIClient(ctx)
		if err != nil {
			return err
		}

		sess, err := resolveDataroomSession(ctx, cfg, client, drID)
		if err != nil {
			return err
		}

		s := ui.NewSpinner()
		s.Start()
		defer s.Stop()

		s.SetLabel("Adding user")
		_, err = client.AddDataroomUser(ctx, drID, email, role)
		if err != nil {
			return fmt.Errorf("adding user: %w", err)
		}

		s.SetLabel("Rekeying dataroom")
		users, err := client.GetDataroomUsers(ctx, drID)
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

		if len(pubKeys) > 0 {
			newEnc, err := crypto.EncryptStringForKeys(sess.PrivateKey, pubKeys)
			if err != nil {
				return fmt.Errorf("encrypting session key: %w", err)
			}
			if err := client.RekeyDataroom(ctx, drID, newEnc); err != nil {
				s.Stop()
				fmt.Fprintf(os.Stderr,
					"warning: %s was added but key rotation failed — "+
						"they cannot access existing content until you re-run this command\n", email)

				return fmt.Errorf("rekeying dataroom: %w", err)
			}
		}
		s.Stop()

		fmt.Printf("Added %s with role %s.\n", email, role)

		return nil
	},
}

// — dataroom user rm —————————————————————————————————————————————————————————

var dataroomUserRmCmd = &cobra.Command{
	Use:   "rm <dataroom_id> <user_id>",
	Short: "Remove a user from a dataroom",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		drID := args[0]
		userID := args[1]

		ctx := cmd.Context()
		cfg, client, err := newAPIClient(ctx)
		if err != nil {
			return err
		}

		sess, err := resolveDataroomSession(ctx, cfg, client, drID)
		if err != nil {
			return err
		}

		s := ui.NewSpinner()
		s.Start()
		defer s.Stop()

		s.SetLabel("Removing user")
		if err := client.RemoveDataroomUser(ctx, drID, userID); err != nil {
			return fmt.Errorf("removing user: %w", err)
		}

		s.SetLabel("Rekeying dataroom")
		users, err := client.GetDataroomUsers(ctx, drID)
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

		if len(pubKeys) > 0 {
			newEnc, err := crypto.EncryptStringForKeys(sess.PrivateKey, pubKeys)
			if err != nil {
				return fmt.Errorf("encrypting session key: %w", err)
			}
			if err := client.RekeyDataroom(ctx, drID, newEnc); err != nil {
				s.Stop()
				fmt.Fprintf(os.Stderr,
					"warning: user %s was removed but key rotation failed — "+
						"their access may persist until you re-run this command\n", userID)

				return fmt.Errorf("rekeying dataroom: %w", err)
			}
		}
		s.Stop()

		fmt.Printf("User %s removed.\n", userID)

		return nil
	},
}

// — dataroom cp ——————————————————————————————————————————————————————————————

var dataroomCpCmd = &cobra.Command{
	Use:   "cp <src...> <dst>",
	Short: "Copy files to or from a dataroom  (local→retyc:// uploads, retyc://→local downloads)",
	Args:  cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		yes, _ := cmd.Flags().GetBool("yes")

		dst := args[len(args)-1]
		srcs := args[:len(args)-1]

		dstURI, dstErr := parseRetycURI(dst)
		srcURI, srcErr := parseRetycURI(srcs[0])

		switch {
		case dstErr == nil && srcErr == nil:
			return fmt.Errorf("remote-to-remote copy is not supported")
		case dstErr != nil && srcErr != nil:
			return fmt.Errorf("either source or destination must be a retyc:// URI")
		case dstErr == nil:
			return dataroomUpload(cmd.Context(), srcs, dstURI, yes)
		default:
			if len(srcs) > 1 {
				return fmt.Errorf("only one remote source is supported for download")
			}

			return dataroomDownload(cmd.Context(), srcURI, dst)
		}
	},
}

func dataroomUpload(ctx context.Context, localPaths []string, dst *retycURI, yes bool) error {
	type statEntry struct {
		path  string
		name  string
		size  int64
		isDir bool
	}

	var entries []statEntry
	var totalSize int64
	for _, p := range localPaths {
		info, err := os.Stat(p)
		if err != nil {
			return err
		}
		size := info.Size()
		if info.IsDir() {
			// Walk the directory to get the real content size.
			size = 0
			_ = filepath.WalkDir(p, func(_ string, d os.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return nil
				}
				fi, err := d.Info()
				if err == nil {
					size += fi.Size()
				}

				return nil
			})
		}
		entries = append(entries, statEntry{
			path:  p,
			name:  info.Name(),
			size:  size,
			isDir: info.IsDir(),
		})
		totalSize += size
	}

	if !yes {
		const lineWidth = 44
		fmt.Fprintln(os.Stderr)
		for _, e := range entries {
			displayName := e.name
			if e.isDir {
				displayName = e.name + "/"
			}
			runes := []rune(displayName)
			if len(runes) > lineWidth-10 {
				displayName = string(runes[:lineWidth-13]) + "…"
			}
			fmt.Fprintf(os.Stderr, "  %-*s  %s\n", lineWidth-10, displayName, ui.FormatSize(e.size))
		}
		fmt.Fprintf(os.Stderr, "  %s\n", strings.Repeat("─", lineWidth))

		var dirCount, fileCount int
		for _, e := range entries {
			if e.isDir {
				dirCount++
			} else {
				fileCount++
			}
		}
		var labelParts []string
		if dirCount == 1 {
			labelParts = append(labelParts, "1 folder")
		} else if dirCount > 1 {
			labelParts = append(labelParts, fmt.Sprintf("%d folders", dirCount))
		}
		if fileCount == 1 {
			labelParts = append(labelParts, "1 file")
		} else if fileCount > 1 {
			labelParts = append(labelParts, fmt.Sprintf("%d files", fileCount))
		}
		fmt.Fprintf(os.Stderr, "  %-*s  %s\n", lineWidth-10, strings.Join(labelParts, ", "), ui.FormatSize(totalSize))
		fmt.Fprintln(os.Stderr)
		fmt.Fprintf(os.Stderr, "  Destination:  retyc://%s%s\n", dst.dataroomID, dst.path)
		fmt.Fprintln(os.Stderr)
		fmt.Fprint(os.Stderr, "Proceed? [y/N] ")
		answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		fmt.Fprintln(os.Stderr)
		if strings.ToLower(strings.TrimSpace(answer)) != "y" {
			fmt.Fprintln(os.Stderr, "Aborted.")

			return nil
		}
	}

	cfg, client, err := newAPIClient(ctx)
	if err != nil {
		return err
	}

	sess, err := resolveDataroomSession(ctx, cfg, client, dst.dataroomID)
	if err != nil {
		return err
	}

	s := ui.NewSpinner()
	s.Start()
	destParentID, err := resolvePath(ctx, client, dst.dataroomID, dst.path, sess.Identity)
	s.Stop()
	if err != nil {
		return err
	}

	// Install SIGINT/SIGTERM handler so the upload loop terminates cleanly and
	// uploadDataroomFile can delete any orphaned node it created before the interrupt.
	uploadCtx, cancelUpload := context.WithCancel(ctx)
	defer cancelUpload()

	var uploadInterrupted atomic.Bool

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	go func() {
		select {
		case <-sigCh:
			uploadInterrupted.Store(true)
			cancelUpload()
		case <-uploadCtx.Done():
		}
	}()

	for _, e := range entries {
		var uploadErr error
		if e.isDir {
			uploadErr = uploadDataroomDir(
				uploadCtx, client, dst.dataroomID, e.path, destParentID,
				sess.PublicKey, sess.Identity, sess.NameSalt,
			)
		} else {
			uploadErr = uploadDataroomFile(
				uploadCtx, client, dst.dataroomID, e.path, destParentID,
				sess.PublicKey, sess.Identity, "", sess.NameSalt,
			)
		}
		if uploadErr != nil {
			if uploadInterrupted.Load() {
				fmt.Fprintln(os.Stderr, "\nUpload interrupted.")

				return fmt.Errorf("interrupted")
			}

			return fmt.Errorf("%s: %w", e.name, uploadErr)
		}
	}

	return nil
}

func dataroomDownload(ctx context.Context, src *retycURI, localDst string) error {
	cfg, client, err := newAPIClient(ctx)
	if err != nil {
		return err
	}

	sess, err := resolveDataroomSession(ctx, cfg, client, src.dataroomID)
	if err != nil {
		return err
	}

	outputDir := localDst
	if outputDir == "" {
		outputDir = "."
	}
	if err := os.MkdirAll(outputDir, 0700); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}

	if hasGlob(src.path) {
		// Glob mode: expand and download all matching file nodes.
		s := ui.NewSpinner()
		s.Start()
		matches, err := resolveGlob(ctx, client, src.dataroomID, src.path, sess.Identity)
		s.Stop()
		if err != nil {
			return err
		}
		if len(matches) == 0 {
			return fmt.Errorf("no nodes match %s", src.path)
		}
		for _, item := range matches {
			if item.Node.TypeEnc == nil {
				name, _ := crypto.DecryptToString(item.Node.NameEnc, sess.Identity)
				fmt.Fprintf(os.Stderr, "  skipping directory: %s\n", name)

				continue
			}
			if item.Version == nil {
				continue
			}
			name, decErr := crypto.DecryptToString(item.Node.NameEnc, sess.Identity)
			if decErr != nil {
				name = item.Node.ID
			}
			if err := downloadDataroomFile(ctx, client, outputDir, item.Version, name, sess.Identity); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			fmt.Fprintf(os.Stderr, "\nDownloaded to %s/%s\n", outputDir, name)
		}

		return nil
	}

	// Single-node mode.
	s := ui.NewSpinner()
	s.Start()
	nodeID, err := resolvePath(ctx, client, src.dataroomID, src.path, sess.Identity)
	if err != nil {
		s.Stop()

		return err
	}
	if nodeID == nil {
		s.Stop()

		return fmt.Errorf("cannot download the root folder")
	}

	item, err := client.GetDataroomNode(ctx, *nodeID)
	s.Stop()
	if err != nil {
		return fmt.Errorf("fetching node: %w", err)
	}
	if item.Node.TypeEnc == nil {
		return fmt.Errorf("%s is a folder — use `ls` to browse it", src.path)
	}
	if item.Version == nil {
		return fmt.Errorf("node has no version yet")
	}

	name, err := crypto.DecryptToString(item.Node.NameEnc, sess.Identity)
	if err != nil {
		name = *nodeID
	}

	if err := downloadDataroomFile(ctx, client, outputDir, item.Version, name, sess.Identity); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}

	fmt.Fprintf(os.Stderr, "\nDownloaded to %s/%s\n", outputDir, name)

	return nil
}

// — dataroom mv ——————————————————————————————————————————————————————————————

var dataroomMvCmd = &cobra.Command{
	Use:   "mv <retyc://src_path> <retyc://dst_path>",
	Short: "Move or rename a node within a dataroom",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		srcURI, err := parseRetycURI(args[0])
		if err != nil {
			return fmt.Errorf("source: %w", err)
		}
		dstURI, err := parseRetycURI(args[1])
		if err != nil {
			return fmt.Errorf("destination: %w", err)
		}
		if srcURI.dataroomID != dstURI.dataroomID {
			return fmt.Errorf("source and destination must be in the same dataroom")
		}

		ctx := cmd.Context()
		cfg, client, err := newAPIClient(ctx)
		if err != nil {
			return err
		}

		sess, err := resolveDataroomSession(ctx, cfg, client, srcURI.dataroomID)
		if err != nil {
			return err
		}

		s := ui.NewSpinner()
		s.Start()
		defer s.Stop()

		srcNodeID, err := resolvePath(ctx, client, srcURI.dataroomID, srcURI.path, sess.Identity)
		if err != nil {
			return err
		}
		if srcNodeID == nil {
			return fmt.Errorf("cannot move the root folder")
		}

		dstParentPath, newName := splitPathParent(dstURI.path)
		if newName == "" {
			return fmt.Errorf("destination path must include a name: %s", args[1])
		}
		dstParentID, err := resolvePath(ctx, client, dstURI.dataroomID, dstParentPath, sess.Identity)
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
		s.Stop()

		fmt.Printf("Moved %s → %s\n", args[0], args[1])

		return nil
	},
}

// — dataroom rm ——————————————————————————————————————————————————————————————

var dataroomRmCmd = &cobra.Command{
	Use:   "rm <retyc://path>",
	Short: "Delete a node, or the whole dataroom when path is omitted (retyc://id)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		uri, err := parseRetycURI(args[0])
		if err != nil {
			return err
		}
		yes, _ := cmd.Flags().GetBool("yes")

		ctx := cmd.Context()
		cfg, client, err := newAPIClient(ctx)
		if err != nil {
			return err
		}

		// Path "/" means delete the whole dataroom — no crypto needed.
		if uri.path == "/" {
			if !yes {
				fmt.Fprintf(os.Stderr, "Delete dataroom %s and all its contents? [y/N] ", uri.dataroomID)
				answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
				if strings.ToLower(strings.TrimSpace(answer)) != "y" {
					fmt.Fprintln(os.Stderr, "Aborted.")

					return nil
				}
			}
			s := ui.NewSpinner()
			s.Start()
			err = client.DeleteDataroom(ctx, uri.dataroomID)
			s.Stop()
			if err != nil {
				return fmt.Errorf("deleting dataroom: %w", err)
			}
			fmt.Printf("Dataroom %s deleted.\n", uri.dataroomID)

			return nil
		}

		sess, err := resolveDataroomSession(ctx, cfg, client, uri.dataroomID)
		if err != nil {
			return err
		}

		s := ui.NewSpinner()

		if hasGlob(uri.path) {
			// Glob mode: expand, confirm, delete all matches.
			s.Start()
			matches, err := resolveGlob(ctx, client, uri.dataroomID, uri.path, sess.Identity)
			s.Stop()
			if err != nil {
				return err
			}
			if len(matches) == 0 {
				return fmt.Errorf("no nodes match %s", args[0])
			}
			if !yes {
				fmt.Fprintln(os.Stderr)
				for _, item := range matches {
					name, _ := crypto.DecryptToString(item.Node.NameEnc, sess.Identity)
					typeLabel := "FILE"
					if item.Node.TypeEnc == nil {
						typeLabel = "DIR"
					}
					fmt.Fprintf(os.Stderr, "  [%s] %s\n", typeLabel, name)
				}
				fmt.Fprintf(os.Stderr, "\nDelete %d node(s) matching %s? [y/N] ", len(matches), args[0])
				answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
				if strings.ToLower(strings.TrimSpace(answer)) != "y" {
					fmt.Fprintln(os.Stderr, "Aborted.")

					return nil
				}
			}
			s.Start()
			for _, item := range matches {
				if err := client.DeleteDataroomNode(ctx, item.Node.ID); err != nil {
					s.Stop()

					return fmt.Errorf("deleting %s: %w", item.Node.ID, err)
				}
			}
			s.Stop()
			fmt.Printf("Deleted %d node(s).\n", len(matches))

			return nil
		}

		// Single-node mode.
		s.Start()
		nodeID, err := resolvePath(ctx, client, uri.dataroomID, uri.path, sess.Identity)
		s.Stop()
		if err != nil {
			return err
		}
		if nodeID == nil {
			return fmt.Errorf("cannot delete the root folder")
		}

		if !yes {
			fmt.Fprintf(os.Stderr, "Delete %s? [y/N] ", args[0])
			answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			if strings.ToLower(strings.TrimSpace(answer)) != "y" {
				fmt.Fprintln(os.Stderr, "Aborted.")

				return nil
			}
		}

		s.Start()
		err = client.DeleteDataroomNode(ctx, *nodeID)
		s.Stop()
		if err != nil {
			return fmt.Errorf("deleting node: %w", err)
		}

		fmt.Printf("Deleted %s\n", args[0])

		return nil
	},
}

// — dataroom mkdir ———————————————————————————————————————————————————————————

var dataroomMkdirCmd = &cobra.Command{
	Use:   "mkdir <retyc://path>",
	Short: "Create a folder in a dataroom",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		uri, err := parseRetycURI(args[0])
		if err != nil {
			return err
		}

		parentPath, name := splitPathParent(uri.path)
		if name == "" {
			return fmt.Errorf("path must include a folder name: %s", args[0])
		}

		ctx := cmd.Context()
		cfg, client, err := newAPIClient(ctx)
		if err != nil {
			return err
		}

		sess, err := resolveDataroomSession(ctx, cfg, client, uri.dataroomID)
		if err != nil {
			return err
		}

		s := ui.NewSpinner()
		s.Start()
		defer s.Stop()

		parentID, err := resolvePath(ctx, client, uri.dataroomID, parentPath, sess.Identity)
		if err != nil {
			return err
		}

		nameEnc, err := crypto.EncryptStringForKeys(name, []string{sess.PublicKey})
		if err != nil {
			return fmt.Errorf("encrypting folder name: %w", err)
		}

		node, err := client.CreateDataroomNode(ctx, uri.dataroomID, nameEnc, nodeNameHash(name, sess.NameSalt), nil, parentID)
		if err != nil {
			return fmt.Errorf("creating folder: %w", err)
		}
		s.Stop()

		fmt.Printf("Created %s (id: %s)\n", args[0], node.ID)

		return nil
	},
}

// — init ——————————————————————————————————————————————————————————————————————

func init() {
	dataroomCreateCmd.Flags().String("title", "", "Title of the dataroom")
	_ = dataroomCreateCmd.MarkFlagRequired("title")

	dataroomUserAddCmd.Flags().String("role", "viewer", "Role: viewer, editor, or admin")

	dataroomCpCmd.Flags().BoolP("yes", "y", false, "Skip confirmation prompt")

	dataroomRmCmd.Flags().BoolP("yes", "y", false, "Skip confirmation prompt")

	dataroomUserCmd.AddCommand(dataroomUserAddCmd)
	dataroomUserCmd.AddCommand(dataroomUserRmCmd)

	dataroomCmd.AddCommand(dataroomLsCmd)
	dataroomCmd.AddCommand(dataroomCreateCmd)
	dataroomCmd.AddCommand(dataroomInfoCmd)
	dataroomCmd.AddCommand(dataroomCpCmd)
	dataroomCmd.AddCommand(dataroomMvCmd)
	dataroomCmd.AddCommand(dataroomRmCmd)
	dataroomCmd.AddCommand(dataroomMkdirCmd)
	dataroomCmd.AddCommand(dataroomUserCmd)

	rootCmd.AddCommand(dataroomCmd)
}

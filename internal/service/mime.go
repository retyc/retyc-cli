package service

import (
	"context"
	"errors"
	"fmt"
	"mime"
	"path/filepath"
	"sync"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/crypto"
)

// defaultMIMEType stands for a file whose extension names no MIME type.
const defaultMIMEType = "application/octet-stream"

// guessMIMEType derives the MIME type stored with a file from its name.
func guessMIMEType(fileName string) string {
	if t := mime.TypeByExtension(filepath.Ext(fileName)); t != "" {
		return t
	}

	return defaultMIMEType
}

// mimeCache is a session's view of its dataroom's MIME table: the MIME type
// of a file is stored once per dataroom, encrypted for the session key, and
// nodes reference it by row ID (api.DataroomMimeType). Reading a listing costs
// one decryption per distinct type instead of one per node; writing a file
// sends the type's hash, plus its ciphertext only for a type the dataroom does
// not know yet.
//
// The table is loaded on first use. An API that predates it answers 404 on
// the route, without an error code: the session is then "legacy", files carry their MIME type as
// the per-node ciphertext type_enc, and nodes are not looked up by name hash
// (the lookup arrived with the table, and an older API would ignore the
// parameter and answer the folder's first page). A load that fails for any
// other reason is not cached: the session behaves as legacy for that call and
// tries again on the next.
type mimeCache struct {
	mu     sync.Mutex
	loaded bool
	legacy bool
	byHash map[string]string // sha256(salt + type) → row ID
	byID   map[string]string // row ID → MIME type
	// missing records row IDs that a reload did not resolve, so a node
	// pointing at an unknown row does not trigger a reload on every listing.
	missing map[string]bool
}

// load fetches the table (or learns that the API has none). c.mu must be held.
func (c *mimeCache) load(ctx context.Context, client *api.Client, dataroomID string, sess *dataroomSession) error {
	rows, err := client.ListDataroomMimeTypes(ctx, dataroomID)
	switch {
	case errors.Is(err, api.ErrNotFound) && !errors.Is(err, api.ErrGone) && api.ErrorCode(err) == "":
		// A 404 with a code (DATAROOM_NOT_FOUND, NOT_A_MEMBER…) is the new
		// API refusing the request, not an older API without the route.
		c.loaded, c.legacy = true, true

		return nil
	case err != nil:
		return fmt.Errorf("fetching MIME types: %w", err)
	}
	c.byHash = make(map[string]string, len(rows))
	c.byID = make(map[string]string, len(rows))
	for _, row := range rows {
		c.byHash[row.Hash] = row.ID
		name, decErr := crypto.DecryptToString(row.NameEnc, sess.Identity)
		if decErr != nil {
			// Encrypted for a key this session does not hold (should not
			// happen: the table is encrypted for the session key). The row
			// still counts as known for writes.
			continue
		}
		c.byID[row.ID] = name
	}
	c.loaded, c.legacy = true, false

	return nil
}

// mimeTable returns the session's MIME table, loading it on first use. The
// returned cache is locked for the caller, who must unlock it.
func (s *dataroomSession) mimeTable(ctx context.Context, client *api.Client, dataroomID string) (*mimeCache, error) {
	c := &s.mime
	c.mu.Lock()
	if !c.loaded {
		if dataroomID == dataroomIDUnknown || client == nil {
			c.mu.Unlock()

			return nil, errors.New("MIME table not loaded and no dataroom to load it from")
		}
		if err := c.load(ctx, client, dataroomID, s); err != nil {
			c.mu.Unlock()

			return nil, err
		}
	}

	return c, nil
}

// nodeTypesSupport reports whether the dataroom's API has the MIME table, and
// with it the explicit node type, the lookup by name hash and the replace
// field of a rename. False without an error is an API known to be older (it
// answered 404 on the table). An error is a probe that failed: nothing is
// known, and the error is the API's, as it is (a rate limit, a 5xx).
func (s *dataroomSession) nodeTypesSupport(
	ctx context.Context, client *api.Client, dataroomID string,
) (bool, error) {
	if client == nil {
		return false, nil
	}
	c, err := s.mimeTable(ctx, client, dataroomID)
	if err != nil {
		return false, err
	}
	defer c.mu.Unlock()

	return !c.legacy, nil
}

// supportsNodeTypes is nodeTypesSupport for a caller that has a way around
// the newer API: a probe that failed counts as an older API for this call, so
// the caller takes the path both APIs accept.
func (s *dataroomSession) supportsNodeTypes(ctx context.Context, client *api.Client, dataroomID string) bool {
	supported, _ := s.nodeTypesSupport(ctx, client, dataroomID)

	return supported
}

// SupportsNameLookup reports whether a node of the dataroom can be looked up
// by its name (LookupNodeByName): the lookup arrived with the MIME table, so
// the same probe answers. False without an error is an older API; an error is
// a probe that failed, which says nothing of the API and is tried again on
// the next call.
func (s *DataroomSession) SupportsNameLookup(
	ctx context.Context, client *api.Client, dataroomID string,
) (bool, error) {
	return s.nodeTypesSupport(ctx, client, dataroomID)
}

// AssumeLegacyAPI records that the dataroom's API predates the MIME table and
// the lookup by name, as the probe does on a 404, and returns the session. A
// test uses it to stand for that API without answering the probe.
func (s *DataroomSession) AssumeLegacyAPI() *DataroomSession {
	s.mime.mu.Lock()
	defer s.mime.mu.Unlock()
	s.mime.loaded, s.mime.legacy = true, true

	return s
}

// mimeTypeOf returns the MIME type of a file node: the row of the MIME table
// it points at, or its legacy per-node ciphertext decrypted. "" when it has
// none, or when the row cannot be resolved.
func (s *dataroomSession) mimeTypeOf(
	ctx context.Context, client *api.Client, dataroomID string, node *api.DataroomNode,
) string {
	if node.MimeTypeID != nil && *node.MimeTypeID != "" && client != nil {
		if name := s.mimeTypeByID(ctx, client, dataroomID, *node.MimeTypeID); name != "" {
			return name
		}
	}
	if node.TypeEnc != nil {
		name, _ := crypto.DecryptToString(*node.TypeEnc, s.Identity)

		return name
	}

	return ""
}

// mimeTypeByID resolves a MIME table row, reloading the table once for a row
// added since it was loaded (a type another client created).
func (s *dataroomSession) mimeTypeByID(ctx context.Context, client *api.Client, dataroomID, id string) string {
	c, err := s.mimeTable(ctx, client, dataroomID)
	if err != nil {
		return ""
	}
	defer c.mu.Unlock()
	if name, ok := c.byID[id]; ok {
		return name
	}
	if c.legacy || c.missing[id] {
		return ""
	}
	if err := c.load(ctx, client, dataroomID, s); err != nil {
		return ""
	}
	if name, ok := c.byID[id]; ok {
		return name
	}
	if c.missing == nil {
		c.missing = make(map[string]bool)
	}
	c.missing[id] = true

	return ""
}

// mimeTypeHeld resolves a MIME table row from the table as the session holds
// it, without ever loading or reloading it: "" for a table not loaded yet, a
// legacy API, or a row added since the load. It makes no request and waits
// for none: mimeCache.mu is held across a load, so a table being loaded is
// one not loaded yet.
func (s *dataroomSession) mimeTypeHeld(id string) string {
	c := &s.mime
	if !c.mu.TryLock() {
		return ""
	}
	defer c.mu.Unlock()

	return c.byID[id]
}

// mimeFor prepares the MIME type of a file about to be written, in the form
// the API expects: the per-node ciphertext on a legacy API or a dataroom
// without name salt (the API refuses an unsalted hash, reversible for a MIME
// type), otherwise the salted hash, with the ciphertext when the dataroom may
// not know the type yet.
func (s *dataroomSession) mimeFor(
	ctx context.Context, client *api.Client, dataroomID, mimeType string,
) (api.NodeMIME, error) {
	if mimeType == "" {
		mimeType = defaultMIMEType
	}
	legacy := s.NameSalt == ""
	var known bool
	hash := nodeNameHash(mimeType, s.NameSalt)
	if !legacy {
		c, err := s.mimeTable(ctx, client, dataroomID)
		if err != nil {
			// Cannot tell which API this is: type_enc is accepted by both.
			legacy = true
		} else {
			legacy = c.legacy
			_, known = c.byHash[hash]
			c.mu.Unlock()
		}
	}
	if legacy {
		enc, err := crypto.EncryptStringForKeys(mimeType, []string{s.PublicKey})
		if err != nil {
			return api.NodeMIME{}, fmt.Errorf("encrypting MIME type: %w", err)
		}

		return api.NodeMIME{TypeEnc: enc}, nil
	}
	m := api.NodeMIME{Hash: hash}
	if !known {
		enc, err := crypto.EncryptStringForKeys(mimeType, []string{s.PublicKey})
		if err != nil {
			return api.NodeMIME{}, fmt.Errorf("encrypting MIME type: %w", err)
		}
		m.NameEnc = enc
	}

	return m, nil
}

// withMIME runs op with the MIME fields for mimeType and handles the API's
// two refusals: 422 mime_type_unknown (the table lost the hash since it was
// loaded: resend with the ciphertext) and 400 mime_types_limit (the dataroom
// holds its maximum of distinct types: fall back to the per-node ciphertext,
// which the API still accepts). On success the hash is recorded as known, so
// the next file of that type sends the hash alone; node, when op returns one,
// also records the row ID for later listings.
func (s *dataroomSession) withMIME(
	ctx context.Context, client *api.Client, dataroomID, mimeType string,
	op func(m api.NodeMIME) (*api.DataroomNode, error),
) error {
	if mimeType == "" {
		mimeType = defaultMIMEType
	}
	m, err := s.mimeFor(ctx, client, dataroomID, mimeType)
	if err != nil {
		return err
	}
	node, err := op(m)
	switch mimeRefusal(err) {
	case api.CodeMimeTypeUnknown:
		if m.Hash == "" || m.NameEnc != "" {
			break
		}
		enc, encErr := crypto.EncryptStringForKeys(mimeType, []string{s.PublicKey})
		if encErr != nil {
			return fmt.Errorf("encrypting MIME type: %w", encErr)
		}
		m.NameEnc = enc
		node, err = op(m)
	case api.CodeMimeTypesLimit:
		if m.TypeEnc != "" {
			break
		}
		enc, encErr := crypto.EncryptStringForKeys(mimeType, []string{s.PublicKey})
		if encErr != nil {
			return fmt.Errorf("encrypting MIME type: %w", encErr)
		}
		m = api.NodeMIME{TypeEnc: enc}
		node, err = op(m)
	}
	if err != nil || m.Hash == "" {
		return err
	}
	s.learnMIME(m.Hash, mimeType, node)

	return nil
}

// mimeRefusal returns the code of a refusal of the MIME fields:
// CodeMimeTypeUnknown, CodeMimeTypesLimit, or anything else. An API without
// codes put them in the detail, which is read only when no code came.
func mimeRefusal(err error) string {
	if code := api.ErrorCode(err); code != "" {
		return code
	}
	switch api.ErrorDetail(err) {
	case api.DetailMimeTypeUnknown:
		return api.CodeMimeTypeUnknown
	case api.DetailMimeTypesLimit:
		return api.CodeMimeTypesLimit
	}

	return ""
}

// learnMIME records that the dataroom knows hash, and its row ID when node
// reports one.
func (s *dataroomSession) learnMIME(hash, mimeType string, node *api.DataroomNode) {
	c := &s.mime
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.loaded || c.legacy {
		return
	}
	id := c.byHash[hash]
	if node != nil && node.MimeTypeID != nil && *node.MimeTypeID != "" {
		id = *node.MimeTypeID
		c.byID[id] = mimeType
	}
	c.byHash[hash] = id
}

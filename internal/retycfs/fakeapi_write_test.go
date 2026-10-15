//go:build linux

package retycfs

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/crypto"
)

// The write routes of fakeAPI. What is uploaded is decrypted with the key of
// its dataroom and kept in the clear, like the files a test puts there: a
// read then gets it back through the same chunks as any other file.
//
// Each kind of request is counted: create_file (node, version and content in
// one request), create_node, version, upload (one chunk), update (rename,
// move, mode), patch (modification time), delete, delete_version.

// fakeUpload is a version being uploaded chunk by chunk: the file does not
// show it before its last chunk.
type fakeUpload struct {
	dr       *fakeDataroom
	nodeID   string
	expected int
	mtime    time.Time
	chunks   map[int][]byte
}

// storageRefusal is the body the API refuses an upload with when the dataroom
// has no room for it.
const storageRefusal = `{"detail":"File size 12 exceeds maximum allowed storage size 0"}`

// refuseUploads makes the API refuse every upload for lack of storage, or
// accept them again.
func (a *fakeAPI) refuseUploads(refuse bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.noStorage = refuse
}

// content returns the content and the modification time of the file name of
// parent as the API holds it, and false when it holds no such file.
func (a *fakeAPI) content(dr *fakeDataroom, parent, name string) ([]byte, time.Time, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := dr.children[parent][name]
	if n == nil || n.kind != api.NodeTypeFile {
		return nil, time.Time{}, false
	}

	return n.data, n.mtime, true
}

// node returns the node name of parent, nil when there is none.
func (a *fakeAPI) node(dr *fakeDataroom, parent, name string) *fakeNode {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := dr.children[parent][name]
	if n == nil {
		return nil
	}
	c := *n

	return &c
}

// locateLocked finds a node by its ID. The caller holds mu.
func (a *fakeAPI) locateLocked(id string) (dr *fakeDataroom, parent, name string, n *fakeNode) {
	for _, dr := range a.datarooms {
		for parent, children := range dr.children {
			for name, n := range children {
				if n.id == id {
					return dr, parent, name, n
				}
			}
		}
	}

	return nil, "", "", nil
}

// mimeLocked resolves the MIME type a write names by its hash, with its
// encrypted name when the table does not hold it yet. The caller holds mu.
func (a *fakeAPI) mimeLocked(dr *fakeDataroom, hash, nameEnc string) (string, bool) {
	if hash == "" {
		return "", true
	}
	key := dr.id + "\x00" + hash
	if nameEnc != "" {
		name, err := crypto.DecryptToString(nameEnc, dr.identity)
		if err != nil {
			return "", false
		}
		a.mimes[key] = name

		return name, true
	}
	if name, ok := a.mimes[key]; ok {
		return name, true
	}
	for _, children := range dr.children {
		for _, n := range children {
			if n.mime != "" && hashOf(dr.salt, n.mime) == hash {
				return n.mime, true
			}
		}
	}

	return "", false
}

func refuse(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

// write answers the routes that change something, and reports whether the
// request was one of them.
func (a *fakeAPI) write(w http.ResponseWriter, r *http.Request, parts []string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	count := len(parts)
	switch {
	case r.Method == http.MethodPost && count == 4 && parts[1] == "node" && parts[3] == "lock":
		a.lockLocked(w, parts[2])
	case r.Method == http.MethodPut && count == 4 && parts[1] == "node" && parts[2] == "lock":
		a.counts["lock_refresh"]++
		if _, held := a.locks[parts[3]]; !held {
			http.Error(w, `{"detail":"Lock not found"}`, http.StatusNotFound)

			break
		}
		writeJSON(w, http.StatusOK, map[string]any{"id": parts[3], "node_id": a.locks[parts[3]]})
	case r.Method == http.MethodDelete && count == 4 && parts[1] == "node" && parts[2] == "lock":
		a.counts["unlock"]++
		if _, held := a.locks[parts[3]]; !held || r.Header.Get("X-Lock-Token") != "token-"+parts[3] {
			http.Error(w, `{"detail":"Lock not found"}`, http.StatusNotFound)

			break
		}
		delete(a.locks, parts[3])
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodPost && count == 4 && parts[2] == "node" && parts[3] == "file":
		a.createFileLocked(w, r, a.datarooms[parts[1]])
	case r.Method == http.MethodPost && count == 4 && parts[2] == "node" && parts[3] == "symlink":
		a.createSymlinkLocked(w, r, a.datarooms[parts[1]])
	case r.Method == http.MethodPost && count == 4 && parts[1] == "node" && parts[3] == "copy":
		a.copyNodeLocked(w, r, parts[2])
	case r.Method == http.MethodPost && count == 3 && parts[2] == "node" && a.datarooms[parts[1]] != nil:
		a.createNodeLocked(w, r, a.datarooms[parts[1]])
	case r.Method == http.MethodPost && count == 4 && parts[1] == "node" && parts[3] == "version":
		a.createVersionLocked(w, r, parts[2])
	case r.Method == http.MethodPost && count == 6 && parts[2] == "version" && parts[4] == "chunk":
		a.uploadChunkLocked(w, r, parts[3], parts[5])
	case r.Method == http.MethodPut && count == 3 && parts[1] == "node":
		a.updateNodeLocked(w, r, parts[2])
	case r.Method == http.MethodPatch && count == 4 && parts[1] == "node" && parts[2] == "version":
		a.patchVersionLocked(w, r, parts[3])
	case r.Method == http.MethodDelete && count == 4 && parts[1] == "node" && parts[2] == "version":
		a.counts["delete_version"]++
		delete(a.uploads, parts[3])
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodDelete && count == 3 && parts[1] == "node":
		a.deleteNodeLocked(w, parts[2])
	default:
		return false
	}

	return true
}

// nameLocked decrypts the name a write gives a node. The caller holds mu.
func (a *fakeAPI) nameLocked(dr *fakeDataroom, nameEnc string) string {
	name, err := crypto.DecryptToString(nameEnc, dr.identity)
	if err != nil {
		a.t.Errorf("a name the dataroom key does not decrypt: %v", err)
	}
	a.cipher[dr.id+"\x00"+name] = nameEnc

	return name
}

func parseTime(text string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, text)

	return t
}

func (a *fakeAPI) createFileLocked(w http.ResponseWriter, r *http.Request, dr *fakeDataroom) {
	a.counts["create_file"]++
	if err := r.ParseMultipartForm(64 << 20); err != nil || dr == nil { //nolint:gosec // G120: test server
		refuse(w, http.StatusBadRequest, `{"detail":"bad request"}`)

		return
	}
	if a.noStorage {
		refuse(w, http.StatusBadRequest, storageRefusal)

		return
	}
	form := r.FormValue
	parent, name := form("parent_id"), a.nameLocked(dr, form("name_enc"))
	mime, ok := a.mimeLocked(dr, form("mime_hash"), form("mime_name_enc"))
	if !ok {
		refuse(w, http.StatusUnprocessableEntity, `{"detail":"`+api.DetailMimeTypeUnknown+`"}`)

		return
	}
	var data []byte
	if files := r.MultipartForm.File["upload_file"]; len(files) > 0 {
		f, _ := files[0].Open()
		enc, _ := io.ReadAll(f)
		plain, err := crypto.DecryptBinary(enc, dr.identity)
		if err != nil {
			a.t.Errorf("a chunk the dataroom key does not decrypt: %v", err)
		}
		data = plain
	}
	if size, _ := strconv.Atoi(form("original_size")); size != len(data) {
		a.t.Errorf("create_file: original_size %d for %d bytes", size, len(data))
	}

	n := dr.children[parent][name]
	switch {
	case n == nil:
		n = &fakeNode{id: a.newID("n"), kind: api.NodeTypeFile, mode: form("access_mode")}
		if dr.children[parent] == nil {
			dr.children[parent] = make(map[string]*fakeNode)
		}
		dr.children[parent][name] = n
	case n.kind != api.NodeTypeFile || form("overwrite") != "true":
		refuse(w, http.StatusConflict, `{"detail":"Name hash conflict in a folder"}`)

		return
	}
	n.mime, n.data, n.version = mime, data, a.newID("v")
	if n.mtime = parseTime(form("client_mtime")); n.mtime.IsZero() {
		n.mtime = time.Now().UTC().Truncate(time.Second)
	}
	// One chunk, whatever its size.
	a.versions[n.version] = fakeVersion{data: data, pub: dr.pub, cut: max(len(data), 1)}

	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(a.itemLocked(dr, parent, name, n))
}

func (a *fakeAPI) createNodeLocked(w http.ResponseWriter, r *http.Request, dr *fakeDataroom) {
	a.counts["create_node"]++
	var body struct {
		ParentID    *string `json:"parent_id"`
		NameEnc     string  `json:"name_enc"`
		Type        string  `json:"type"`
		MimeHash    string  `json:"mime_hash"`
		MimeNameEnc string  `json:"mime_name_enc"`
		AccessMode  string  `json:"access_mode"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	parent := ""
	if body.ParentID != nil {
		parent = *body.ParentID
	}
	name := a.nameLocked(dr, body.NameEnc)
	if dr.children[parent][name] != nil {
		refuse(w, http.StatusConflict, `{"detail":"Name hash conflict in a folder"}`)

		return
	}
	n := &fakeNode{id: a.newID("n"), kind: body.Type, mode: body.AccessMode}
	if n.kind == api.NodeTypeFile {
		mime, ok := a.mimeLocked(dr, body.MimeHash, body.MimeNameEnc)
		if !ok {
			refuse(w, http.StatusUnprocessableEntity, `{"detail":"`+api.DetailMimeTypeUnknown+`"}`)

			return
		}
		n.mime = mime
	}
	if dr.children[parent] == nil {
		dr.children[parent] = make(map[string]*fakeNode)
	}
	dr.children[parent][name] = n
	_ = json.NewEncoder(w).Encode(a.itemLocked(dr, parent, name, n)["node"])
}

// createSymlinkLocked creates a symbolic link, its target encrypted like its
// name.
func (a *fakeAPI) createSymlinkLocked(w http.ResponseWriter, r *http.Request, dr *fakeDataroom) {
	a.counts["symlink"]++
	var body struct {
		ParentID  *string `json:"parent_id"`
		NameEnc   string  `json:"name_enc"`
		TargetEnc string  `json:"target_enc"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if dr == nil {
		refuse(w, http.StatusNotFound, `{"detail":"Dataroom not found"}`)

		return
	}
	parent := ""
	if body.ParentID != nil {
		parent = *body.ParentID
	}
	name := a.nameLocked(dr, body.NameEnc)
	if dr.children[parent][name] != nil {
		refuse(w, http.StatusConflict, `{"detail":"Name hash conflict in a folder"}`)

		return
	}
	target, err := crypto.DecryptToString(body.TargetEnc, dr.identity)
	if err != nil {
		a.t.Errorf("a target the dataroom key does not decrypt: %v", err)
	}
	n := &fakeNode{id: a.newID("n"), kind: api.NodeTypeSymlink, target: target}
	if dr.children[parent] == nil {
		dr.children[parent] = make(map[string]*fakeNode)
	}
	dr.children[parent][name] = n
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(a.itemLocked(dr, parent, name, n)["node"])
}

// copyNodeLocked is the server-side copy of a file: a new node holding the
// content of the current version of the source, cut the same way, complete
// at once. It keeps the mode, the MIME type and the modification time.
func (a *fakeAPI) copyNodeLocked(w http.ResponseWriter, r *http.Request, nodeID string) {
	a.counts["copy"]++
	var body struct {
		ParentID *string `json:"parent_id"`
		NameEnc  string  `json:"name_enc"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	dr, _, _, src := a.locateLocked(nodeID)
	if src == nil || src.kind != api.NodeTypeFile || src.version == "" {
		refuse(w, http.StatusNotFound, `{"detail":"Node not found"}`)

		return
	}
	if a.noStorage {
		refuse(w, http.StatusBadRequest, storageRefusal)

		return
	}
	parent := ""
	if body.ParentID != nil {
		parent = *body.ParentID
	}
	name := a.nameLocked(dr, body.NameEnc)
	if dr.children[parent][name] != nil {
		refuse(w, http.StatusConflict, `{"detail":"Name hash conflict in a folder"}`)

		return
	}
	n := &fakeNode{
		id: a.newID("n"), kind: api.NodeTypeFile, mode: src.mode, mime: src.mime,
		data: src.data, version: a.newID("v"), mtime: src.mtime,
	}
	a.versions[n.version] = a.versions[src.version]
	if dr.children[parent] == nil {
		dr.children[parent] = make(map[string]*fakeNode)
	}
	dr.children[parent][name] = n
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(a.itemLocked(dr, parent, name, n))
}

func (a *fakeAPI) createVersionLocked(w http.ResponseWriter, r *http.Request, nodeID string) {
	a.counts["version"]++
	dr, _, _, n := a.locateLocked(nodeID)
	if n == nil {
		refuse(w, http.StatusNotFound, `{"detail":"Node not found"}`)

		return
	}
	if a.noStorage {
		refuse(w, http.StatusBadRequest, storageRefusal)

		return
	}
	var body struct {
		OriginalSize int64  `json:"original_size"`
		Expected     int    `json:"chunk_count_expected"`
		ClientMtime  string `json:"client_mtime"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	id := a.newID("v")
	a.uploads[id] = &fakeUpload{
		dr: dr, nodeID: nodeID, expected: body.Expected, mtime: parseTime(body.ClientMtime), chunks: map[int][]byte{},
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"id": id, "node_id": nodeID, "original_size": body.OriginalSize, "chunk_count": 0,
		"chunk_count_expected": body.Expected, "created_at": "2026-10-02T09:00:00Z",
	})
}

func (a *fakeAPI) uploadChunkLocked(w http.ResponseWriter, r *http.Request, versionID, indexText string) {
	a.counts["upload"]++
	up := a.uploads[versionID]
	index, err := strconv.Atoi(indexText)
	if up == nil || err != nil {
		refuse(w, http.StatusNotFound, `{"detail":"Version not found"}`)

		return
	}
	if err := r.ParseMultipartForm(64 << 20); err != nil { //nolint:gosec // G120: test server
		refuse(w, http.StatusBadRequest, `{"detail":"bad request"}`)

		return
	}
	if _, stored := up.chunks[index]; stored || index >= up.expected {
		refuse(w, http.StatusUnprocessableEntity, `{"detail":"Chunk refused"}`)

		return
	}
	f, _ := r.MultipartForm.File["upload_file"][0].Open()
	enc, _ := io.ReadAll(f)
	plain, err := crypto.DecryptBinary(enc, up.dr.identity)
	if err != nil {
		a.t.Errorf("a chunk the dataroom key does not decrypt: %v", err)
	}
	up.chunks[index] = plain
	w.WriteHeader(http.StatusCreated)
	if len(up.chunks) < up.expected {
		return
	}

	// The last chunk: the version is complete, and the file shows it.
	delete(a.uploads, versionID)
	_, _, _, n := a.locateLocked(up.nodeID)
	if n == nil {
		return
	}
	var data []byte
	for i := range up.expected {
		data = append(data, up.chunks[i]...)
	}
	n.data, n.version, n.mtime = data, versionID, up.mtime
	if n.mtime.IsZero() {
		n.mtime = time.Now().UTC().Truncate(time.Second)
	}
	// Cut as its uploader cut it.
	a.versions[versionID] = fakeVersion{data: data, pub: up.dr.pub, cut: max(len(up.chunks[0]), 1)}
}

func (a *fakeAPI) updateNodeLocked(w http.ResponseWriter, r *http.Request, nodeID string) {
	a.counts["update"]++
	dr, parent, name, n := a.locateLocked(nodeID)
	if n == nil {
		refuse(w, http.StatusNotFound, `{"detail":"Node not found"}`)

		return
	}
	var body map[string]json.RawMessage
	_ = json.NewDecoder(r.Body).Decode(&body)
	text := func(field string) (value string) {
		_ = json.Unmarshal(body[field], &value)

		return value
	}
	if mode := text("access_mode"); mode != "" {
		n.mode = mode
	}
	nameEnc := text("name_enc")
	if nameEnc == "" {
		_, _ = io.WriteString(w, "{}")

		return
	}
	newName, newParent := a.nameLocked(dr, nameEnc), parent
	if _, moved := body["parent_id"]; moved {
		newParent = text("parent_id")
	}
	if holder := dr.children[newParent][newName]; holder != nil && holder != n {
		switch {
		case string(body["replace"]) != "true":
			refuse(w, http.StatusConflict, `{"detail":"Name hash conflict in a folder"}`)

			return
		case holder.kind == api.NodeTypeFolder:
			refuse(w, http.StatusConflict, `{"detail":"Cannot replace a folder"}`)

			return
		}
	}
	delete(dr.children[parent], name)
	if dr.children[newParent] == nil {
		dr.children[newParent] = make(map[string]*fakeNode)
	}
	dr.children[newParent][newName] = n
	_, _ = io.WriteString(w, "{}")
}

func (a *fakeAPI) patchVersionLocked(w http.ResponseWriter, r *http.Request, versionID string) {
	a.counts["patch"]++
	var body struct {
		ClientMtime string `json:"client_mtime"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	for _, dr := range a.datarooms {
		for _, children := range dr.children {
			for _, n := range children {
				if n.version == versionID {
					// A timestamp of microseconds, as the API stores it.
					n.mtime = parseTime(body.ClientMtime).Truncate(time.Microsecond)
					_, _ = io.WriteString(w, "{}")

					return
				}
			}
		}
	}
	refuse(w, http.StatusNotFound, `{"detail":"Version not found"}`)
}

func (a *fakeAPI) deleteNodeLocked(w http.ResponseWriter, nodeID string) {
	a.counts["delete"]++
	if a.undeletable[nodeID] {
		refuse(w, http.StatusForbidden, `{"detail":"Forbidden"}`)

		return
	}
	dr, parent, name, n := a.locateLocked(nodeID)
	if n == nil {
		refuse(w, http.StatusNotFound, `{"detail":"Node not found"}`)

		return
	}
	delete(dr.children[parent], name)
	a.dropTreeLocked(dr, n.id)
	w.WriteHeader(http.StatusNoContent)
}

// dropTreeLocked removes what the folder id holds. The caller holds mu.
func (a *fakeAPI) dropTreeLocked(dr *fakeDataroom, id string) {
	for _, n := range dr.children[id] {
		a.dropTreeLocked(dr, n.id)
	}
	delete(dr.children, id)
}

// lockLocked answers POST /dataroom/node/{id}/lock: one exclusive lock per
// node, 423 while another is held, by this client or by another
// (lockedElsewhere). The caller holds mu.
func (a *fakeAPI) lockLocked(w http.ResponseWriter, nodeID string) {
	a.counts["lock"]++
	held := a.lockedElsewhere[nodeID]
	for _, id := range a.locks {
		held = held || id == nodeID
	}
	if held {
		http.Error(w, `{"detail":"Node is locked"}`, http.StatusLocked)

		return
	}
	a.lockSeq++
	id := fmt.Sprintf("lock-%d", a.lockSeq)
	a.locks[id] = nodeID
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": id, "node_id": nodeID, "kind": "exclusive", "token": "token-" + id,
	})
}

// locksHeld returns the number of locks the API holds for this client.
func (a *fakeAPI) locksHeld() int {
	a.mu.Lock()
	defer a.mu.Unlock()

	return len(a.locks)
}

// writeJSON answers status with v as JSON.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

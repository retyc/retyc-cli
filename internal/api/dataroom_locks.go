// Package api — dataroom node locks, server-side copy and version lookup.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

// Lock kinds. Shared locks are compatible with each other; an exclusive lock
// is alone on its node.
const (
	LockShared    = "shared"
	LockExclusive = "exclusive"
)

// Lock lease bounds, in seconds. A lock not refreshed within its lease
// expires; a crashed holder blocks others for LockTimeoutMax at most.
const (
	LockTimeoutMin     = 10
	LockTimeoutDefault = 120
	LockTimeoutMax     = 300
)

// lockTokenHeader proves the detention of a lock on refresh and release.
const lockTokenHeader = "X-Lock-Token" //nolint:gosec // G101: header name, not a credential

// NodeLock is an advisory whole-file lock on a dataroom node (WebDAV LOCK
// semantics): the server arbitrates between locks, it refuses no write.
// Token is set only by LockDataroomNode, once; it proves the detention of the
// lock, not a role, so two mounts of the same user are two holders.
type NodeLock struct {
	ID         string    `json:"id"`
	NodeID     string    `json:"node_id"`
	DataroomID string    `json:"dataroom_id"`
	UserID     string    `json:"user_id"`
	Kind       string    `json:"kind"`
	ExpiresAt  time.Time `json:"expires_at"`
	CreatedAt  time.Time `json:"created_at"`
	Token      string    `json:"token,omitempty"`
}

// clampLockTimeout brings a lease into the server's bounds.
func clampLockTimeout(seconds int) int {
	return min(max(seconds, LockTimeoutMin), LockTimeoutMax)
}

// LockDataroomNode takes a lock of kind on the file nodeID for timeout
// seconds (clamped to the lease bounds). It answers ErrLocked when another
// lock excludes it, a 403 for an exclusive lock on a file the caller cannot
// write, a 422 for a folder, ErrGone for a node pending deletion.
func (c *Client) LockDataroomNode(ctx context.Context, nodeID, kind string, timeout int) (*NodeLock, error) {
	data, err := json.Marshal(map[string]any{"kind": kind, "timeout": clampLockTimeout(timeout)})
	if err != nil {
		return nil, err
	}
	var result NodeLock
	if err := c.Post(ctx, "/dataroom/node/"+nodeID+"/lock", bytes.NewReader(data), &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// RefreshDataroomNodeLock extends the lease of lockID by timeout seconds
// (clamped). A lease that ended answers ErrGone, one already purged
// ErrNotFound: either way the lock is lost and a new one must be taken.
func (c *Client) RefreshDataroomNodeLock(ctx context.Context, lockID, token string, timeout int) (*NodeLock, error) {
	data, err := json.Marshal(map[string]any{"timeout": clampLockTimeout(timeout)})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.baseURL+"/dataroom/node/lock/"+lockID,
		bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set(lockTokenHeader, token)
	var result NodeLock
	if err := c.do(req, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// UnlockDataroomNode releases lockID. A lock already purged answers
// ErrNotFound, which a caller releasing a lost lock can ignore.
func (c *Client) UnlockDataroomNode(ctx context.Context, lockID, token string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/dataroom/node/lock/"+lockID, nil)
	if err != nil {
		return err
	}
	req.Header.Set(lockTokenHeader, token)

	return c.do(req, nil)
}

// ListDataroomNodeLocks returns the active locks of a file (without tokens).
func (c *Client) ListDataroomNodeLocks(ctx context.Context, nodeID string) ([]NodeLock, error) {
	var result []NodeLock
	if err := c.Get(ctx, "/dataroom/node/"+nodeID+"/locks", &result); err != nil {
		return nil, err
	}

	return result, nil
}

// ListDataroomLocks returns the active locks of a dataroom (without tokens).
func (c *Client) ListDataroomLocks(ctx context.Context, dataroomID string) ([]NodeLock, error) {
	var result []NodeLock
	if err := c.Get(ctx, "/dataroom/"+dataroomID+"/locks", &result); err != nil {
		return nil, err
	}

	return result, nil
}

// CopyDataroomNode copies the last complete version of the file nodeID into
// a new node named nameEnc / nameHash under parentID (nil for the root) of
// the same dataroom. The storage duplicates the chunks (nothing transits
// through the API); the copy keeps the source's MIME type, mode and
// client_mtime.
//
// The API answers 202: the new node is listed at once with a version whose
// ChunkCount is 0 and ChunkCountExpected the source's count; it becomes
// downloadable when the two meet (poll GetDataroomNodeVersion). A 404 on
// that version later means the copy was discarded, a 410 that the node was
// deleted meanwhile. Errors: ErrConflict when the name is held, ErrNotFound
// for the source or the destination folder, a 422 for a folder or a file
// without a complete version, a 400 when the copy exceeds the storage, a
// 503 when the copy queue is unavailable (retry later).
func (c *Client) CopyDataroomNode(
	ctx context.Context, nodeID string, parentID *string, nameEnc, nameHash string,
) (*DataroomNodeItem, error) {
	data, err := json.Marshal(map[string]any{"parent_id": parentID, "name_enc": nameEnc, "name_hash": nameHash})
	if err != nil {
		return nil, err
	}
	var result DataroomNodeItem
	if err := c.Post(ctx, "/dataroom/node/"+nodeID+"/copy", bytes.NewReader(data), &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetDataroomNodeVersion fetches one version, to follow the progress of a
// copy or an upload another client is making (ChunkCount against
// ChunkCountExpected).
func (c *Client) GetDataroomNodeVersion(ctx context.Context, versionID string) (*DataroomNodeVersion, error) {
	var result DataroomNodeVersion
	if err := c.Get(ctx, "/dataroom/node/version/"+versionID, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// FormatLockTimeout renders a lease the way the WebDAV Timeout header does.
func FormatLockTimeout(seconds int) string {
	return "Second-" + strconv.Itoa(seconds)
}

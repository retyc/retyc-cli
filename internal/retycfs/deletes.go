//go:build linux

package retycfs

import (
	"context"
	"sync"
	"syscall"

	"github.com/retyc/retyc-cli/internal/metrics"
	"github.com/retyc/retyc-cli/internal/vfs"
)

// DefaultDeleteConcurrency is the number of background deletes a mount built
// with a zero Options.DeleteConcurrency sends at once.
const DefaultDeleteConcurrency = 4

// deleteQueue sends the deletes unlink(2) answered before the API did
// (Options.BackgroundDelete), a bounded number at once.
//
// A file removed that way is absent from the mount at once (vfs.FS.HideNode)
// and is deleted at the API later. Until then the API still holds its name:
// whatever needs that name free there waits for the delete first (waitName,
// waitFolder).
//
// A nil queue is one of a mount without the option: nothing waits on it.
type deleteQueue struct {
	drv *driver
	// slots bounds the deletes at the API at once.
	slots chan struct{}
	// busy counts the deletes not ended yet, which a shutdown waits for.
	busy *inflight

	mu   sync.Mutex
	jobs map[*deleteJob]struct{}
}

// deleteKey is a name in a folder, as the API holds it: the folder by its
// node (empty for the root of the dataroom), which a rename of the folder
// does not change.
type deleteKey struct {
	dataroomID, folderID, name string
}

// deleteJob is one delete on its way.
type deleteJob struct {
	key deleteKey
	// dir is the folder the node was removed from and path the path it had
	// then: the listing to drop when the delete fails.
	dir    *dirNode
	path   string
	nodeID string
	// done is closed once the API has answered and the outcome is recorded.
	done chan struct{}
	// lost: reported as not deleted before the end of the drain. Guarded by
	// deleteQueue.mu.
	lost bool
}

func newDeleteQueue(d *driver, concurrency int) *deleteQueue {
	if concurrency <= 0 {
		concurrency = DefaultDeleteConcurrency
	}

	return &deleteQueue{
		drv:   d,
		slots: make(chan struct{}, concurrency),
		busy:  newInflight(),
		jobs:  make(map[*deleteJob]struct{}),
	}
}

// add queues the delete of node, removed under name from the folder dir,
// whose path is path. The node is already hidden (vfs.FS.HideNode).
func (q *deleteQueue) add(dir *dirNode, path, name string, node vfs.Node) {
	j := &deleteJob{
		key:    deleteKey{dataroomID: dir.dataroomID, folderID: dir.nodeID, name: name},
		dir:    dir,
		path:   path,
		nodeID: node.ID,
		done:   make(chan struct{}),
	}
	q.mu.Lock()
	q.jobs[j] = struct{}{}
	q.mu.Unlock()
	finished := q.busy.begin()
	go func() {
		defer finished()
		q.end(j, q.send(j))
	}()
}

// send asks the API for the delete once a slot is free, in a trace of its
// own: the unlink that queued it has answered. It carries identifiers only.
// Only the end of the drain of a shutdown cancels it.
func (q *deleteQueue) send(j *deleteJob) error {
	stopped := q.drv.stopped
	select {
	case q.slots <- struct{}{}:
		defer func() { <-q.slots }()
	case <-stopped.Done():
		return context.Cause(stopped)
	}
	ctx, span := startSpan(stopped, "background_delete", j.key.dataroomID, j.nodeID)
	err := q.drv.tree.DeleteNode(ctx, j.nodeID)
	span.End(err)

	return err
}

// end records the outcome of a delete. One that failed leaves the file in
// the dataroom: it is shown again, the listing of its folder is dropped, and
// the operator is told, by identifiers.
func (q *deleteQueue) end(j *deleteJob, err error) {
	d := q.drv
	path := j.path
	if now, ok := j.dir.path(); ok {
		// The folder may have been renamed since.
		path = now
	}
	d.tree.RevealNode(j.key.dataroomID, path, j.nodeID, err == nil)

	q.mu.Lock()
	delete(q.jobs, j)
	if err != nil && d.drainCut() {
		q.loseLocked(j)
	}
	lost := j.lost
	q.mu.Unlock()
	close(j.done)

	if err == nil {
		// Deleted, even when the drain had given it up meanwhile.
		metrics.FuseBackgroundDeletes.WithLabelValues("ok").Inc()

		return
	}
	metrics.FuseBackgroundDeletes.WithLabelValues("error").Inc()
	// The kernel may hold that the name is missing.
	d.notify.entry(j.dir.EmbeddedInode(), j.key.name)
	if !lost {
		// Neither the error nor the name: both may hold a file name.
		d.logf("a background delete failed, the file is still in the dataroom: dataroom %s, node %s: %s",
			j.key.dataroomID, j.nodeID, errnoName(toErrno(err)))
	}
}

// loseLocked reports, once, a delete the end of the drain cut. The caller
// holds mu.
func (q *deleteQueue) loseLocked(j *deleteJob) {
	if j.lost {
		return
	}
	j.lost = true
	q.drv.lostDeletes.Add(1)
	q.drv.logf("a background delete did not end before the end of the shutdown drain, "+
		"the file may still be in the dataroom: dataroom %s, node %s", j.key.dataroomID, j.nodeID)
}

// drain waits for the deletes on their way, for as long as the drain of the
// shutdown lasts. Those it does not see the end of are reported lost before
// it returns.
func (q *deleteQueue) drain() {
	if q == nil || q.busy.wait(q.drv.stopped) {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	for j := range q.jobs {
		q.loseLocked(j)
	}
}

// waitName returns once no delete is on its way for the name in the folder
// dir, or with the error of ctx.
func (q *deleteQueue) waitName(ctx context.Context, dir *dirNode, name string) error {
	if q == nil || dir == nil {
		return nil
	}
	key := deleteKey{dataroomID: dir.dataroomID, folderID: dir.nodeID, name: name}

	return q.wait(ctx, func(j *deleteJob) bool { return j.key == key })
}

// waitAt is waitName for the place at.
func (q *deleteQueue) waitAt(ctx context.Context, at location) error {
	if q == nil {
		return nil
	}
	dir, _ := parentDir(at)

	return q.waitName(ctx, dir, at.name)
}

// waitFolder returns once no delete is on its way for a child of the folder
// dir, or with the error of ctx.
func (q *deleteQueue) waitFolder(ctx context.Context, dir *dirNode) error {
	if q == nil || dir == nil {
		return nil
	}

	return q.wait(ctx, func(j *deleteJob) bool {
		return j.key.dataroomID == dir.dataroomID && j.key.folderID == dir.nodeID
	})
}

// wait returns once no delete that matches is on its way.
func (q *deleteQueue) wait(ctx context.Context, match func(*deleteJob) bool) error {
	for {
		var pending []*deleteJob
		q.mu.Lock()
		for j := range q.jobs {
			if match(j) {
				pending = append(pending, j)
			}
		}
		q.mu.Unlock()
		if len(pending) == 0 {
			return nil
		}
		for _, j := range pending {
			select {
			case <-j.done:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}

// unlinkLater is Unlink with Options.BackgroundDelete: the node called name
// is made absent from the mount and its delete is queued. It asks the API
// nothing when the listing of the folder is cached, which it is after the
// lookup the kernel made. handled is false for what is removed while the
// request waits, as without the option: a folder.
//
// sp is the spool of the file when it is being written, which is unlinked as
// in Unlink.
func (n *dirNode) unlinkLater(ctx context.Context, name string, sp *openSpool) (handled bool, errno syscall.Errno) {
	ctx, span := startSpan(ctx, "unlink", n.dataroomID, n.nodeID)
	var (
		node vfs.Node
		dir  string
	)
	err := n.withPath(ctx, func(path string) error {
		found, err := n.drv.tree.Lookup(ctx, n.dataroomID, path, name)
		if err != nil || found.Type == vfs.TypeDir || found.ID == "" {
			return err
		}
		n.drv.tree.HideNode(n.dataroomID, path, found)
		node, dir = found, path

		return nil
	})
	span.End(err)
	switch {
	case err != nil:
		return true, pathErrno(err)
	case node.ID == "":
		return false, 0
	}
	n.drv.deletes.add(n, dir, name, node)
	st := stateOf(n.GetChild(name))
	if sp != nil {
		st = sp.st
	}
	n.unlinked(sp, st)

	return true, 0
}

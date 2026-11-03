package vfs

import (
	"context"
	"errors"
	"os"
	"path"
	"sync"
	"time"

	"go.opentelemetry.io/otel/trace"

	"github.com/retyc/retyc-cli/internal/auth"
	"github.com/retyc/retyc-cli/internal/metrics"
	"github.com/retyc/retyc-cli/internal/telemetry"
)

// WarmupStats is what a Warmup walked.
type WarmupStats struct {
	// Folders is the number of folders listed, Files the number of files
	// they hold (symbolic links are neither), Errors the number of folders
	// that could not be listed.
	Folders, Files, Errors int
	Duration               time.Duration
	// Interrupted tells a walk stopped before its end: its context ended, or
	// the login was lost.
	Interrupted bool
}

// warmTask is one folder for the walk to list. depth is its level, the root
// of a dataroom being 1.
type warmTask struct {
	dataroomID, path string
	depth            int
}

// warmWalk is the state of a Warmup: a queue of folders, read by
// Options.ListConcurrency workers.
type warmWalk struct {
	fs       *FS
	ctx      context.Context
	stop     context.CancelFunc
	maxDepth int

	mu    sync.Mutex
	cond  *sync.Cond
	queue []warmTask
	// pending is the number of tasks queued or being listed: the walk is
	// over when it reaches zero.
	pending int
	stats   WarmupStats
}

// Warmup fills the listing cache with every folder of the dataroom, or of
// every dataroom the user can reach when dataroomID is empty, as a `find`
// run right after mounting would: one listing per folder, through the cache.
// It returns once the walk is over or ctx ends, never with an error: a folder
// that cannot be listed is reported through Options.Logf, counted, and its
// subtree skipped. Only a lost login stops the walk early, every listing
// after it failing the same way.
//
// maxDepth bounds the levels listed in each dataroom, its root being the
// first; 0 lists them all. Symbolic links are not followed.
//
// The walk is a background client of the cache: a listing still fresh, in
// memory or in a shared store, is not fetched again, and a fetch queues for
// one of the refresh slots (Options.ListConcurrency) like the refresh of an
// expired listing, so the walk and the refreshes together never run more
// listings at once than that. A request that needs a folder being fetched
// joins the fetch and lets it start at once. A fetch already started when ctx
// ends completes on its own, like any other (at most ListConcurrency of
// them).
//
// Nothing is decided on the walk's answers: a mutation landing meanwhile
// follows the usual rules (see ReadDir), and the walk never writes.
func (fs *FS) Warmup(ctx context.Context, dataroomID string, maxDepth int) WarmupStats {
	start := time.Now()
	ctx, span := telemetry.Tracer().Start(ctx, "cache.warmup",
		trace.WithNewRoot(), trace.WithSpanKind(trace.SpanKindInternal))
	defer span.End()
	ctx, stop := context.WithCancel(ctx)
	defer stop()

	w := &warmWalk{fs: fs, ctx: ctx, stop: stop, maxDepth: maxDepth}
	w.cond = sync.NewCond(&w.mu)
	defer context.AfterFunc(ctx, func() {
		w.mu.Lock()
		w.cond.Broadcast()
		w.mu.Unlock()
	})()

	for _, id := range w.roots(dataroomID) {
		w.queue = append(w.queue, warmTask{dataroomID: id, path: "/", depth: 1})
	}
	w.pending = len(w.queue)

	var wg sync.WaitGroup
	for range fs.opts.listConcurrency() {
		wg.Go(w.work)
	}
	wg.Wait()

	w.stats.Duration = time.Since(start)
	w.stats.Interrupted = w.stats.Interrupted || ctx.Err() != nil
	metrics.WarmupDuration.Set(w.stats.Duration.Seconds())

	return w.stats
}

// roots returns the datarooms to walk: dataroomID, or every dataroom of the
// user when it is empty. A list that cannot be read is counted as a failed
// folder, the one the datarooms are the entries of.
func (w *warmWalk) roots(dataroomID string) []string {
	if dataroomID != "" {
		return []string{dataroomID}
	}
	datarooms, err := w.fs.Datarooms(w.ctx)
	if err != nil {
		w.failed("", err)

		return nil
	}
	ids := make([]string, 0, len(datarooms))
	for _, d := range datarooms {
		ids = append(ids, d.ID)
	}

	return ids
}

// work lists the folders of the queue until the walk is over.
func (w *warmWalk) work() {
	for {
		task, ok := w.next()
		if !ok {
			return
		}
		w.done(w.list(task))
	}
}

// next takes the next folder of the queue, waiting while the queue is empty
// and folders are still being listed (their children are to come). It
// reports false once the walk is over or stopped.
func (w *warmWalk) next() (warmTask, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for len(w.queue) == 0 && w.pending > 0 && w.ctx.Err() == nil {
		w.cond.Wait()
	}
	if len(w.queue) == 0 || w.ctx.Err() != nil {
		return warmTask{}, false
	}
	// First in, first out: the levels near the root, those an application
	// scanning its volume reaches first, are warm first.
	task := w.queue[0]
	w.queue[0] = warmTask{}
	w.queue = w.queue[1:]

	return task, true
}

// done queues the children of a folder just listed, and wakes the workers.
func (w *warmWalk) done(children []warmTask) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.queue = append(w.queue, children...)
	w.pending += len(children) - 1
	w.cond.Broadcast()
}

// list lists one folder and returns its subfolders to walk.
func (w *warmWalk) list(task warmTask) []warmTask {
	nodes, err := w.fs.warmListing(w.ctx, task.dataroomID, task.path)
	switch {
	case w.ctx.Err() != nil:
		return nil
	case errors.Is(err, os.ErrNotExist):
		// Deleted since its parent was listed: nothing to warm.
		return nil
	case err != nil:
		w.failed(task.dataroomID, err)
		if errors.Is(err, auth.ErrNoToken) || errors.Is(err, auth.ErrNoRefreshToken) {
			w.mu.Lock()
			w.stats.Interrupted = true
			w.mu.Unlock()
			w.stop()
		}

		return nil
	}
	metrics.WarmupFolders.WithLabelValues("ok").Inc()
	var children []warmTask
	files := 0
	for _, n := range nodes {
		switch n.Type {
		case TypeFile:
			files++
		case TypeDir:
			if w.maxDepth == 0 || task.depth < w.maxDepth {
				children = append(children, warmTask{
					dataroomID: task.dataroomID, path: path.Join(task.path, n.Name), depth: task.depth + 1,
				})
			}
		}
	}
	w.mu.Lock()
	w.stats.Folders++
	w.stats.Files += files
	w.mu.Unlock()

	return children
}

// failed counts a folder that could not be listed and tells the operator,
// by dataroom ID only: never a path or a name.
func (w *warmWalk) failed(dataroomID string, err error) {
	metrics.WarmupFolders.WithLabelValues("error").Inc()
	w.mu.Lock()
	w.stats.Errors++
	w.mu.Unlock()
	if dataroomID == "" {
		w.fs.logf("warmup: the dataroom list could not be read: %s", err)

		return
	}
	w.fs.logf("warmup: a folder of dataroom %s could not be listed, skipped: %s", dataroomID, err)
}

// warmListing returns the listing of a folder no older than the TTL, as
// readDirRefreshed does, but fetched as a background refresh is: queued for a
// refresh slot, promoted by a request that joins it. It records no cache
// lookup: the walk is not a client whose hits tell anything.
func (fs *FS) warmListing(ctx context.Context, dataroomID, path string) ([]Node, error) {
	key := listingKey(dataroomID, path)
	fs.mu.Lock()
	if l, ok := fs.heldLocked(fs.leaveSealed(ctx), key); ok && time.Since(l.FetchedAt) < fs.opts.ttl() {
		fs.unlock()
		if l, ok = fs.openListing(ctx, dataroomID, l); ok { // out of mu (see leaveSealed)
			return l.Nodes, nil
		}
		fs.mu.Lock()
	}
	f := fs.fetchLocked(ctx, key, true)
	fs.unlock()

	return f.wait(ctx)
}

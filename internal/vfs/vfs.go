// Package vfs is the service layer shared by the front ends that present
// datarooms as a file tree: the WebDAV server today, a FUSE driver later. It
// holds the caches and the coordination around them, and knows nothing of the
// protocol that serves them.
//
// Dependency rule, enforced by TestDependencyRule: the package and its
// sub-packages import neither net/http, golang.org/x/net/webdav, go-fuse,
// cobra, viper, internal/config nor cmd. internal/config and viper still come
// in through internal/api and internal/service, which vfs builds on; a front
// end (x/net/webdav, go-fuse, cobra, cmd) must not, even indirectly. Settings
// arrive through Options, as plain values.
package vfs

import (
	"context"
	"os"
	"time"

	"filippo.io/age"

	"github.com/retyc/retyc-cli/internal/service"
	"github.com/retyc/retyc-cli/internal/vfs/metastore"
)

// DefaultCacheTTL is the TTL of a cache built with a zero Options.TTL. It
// equals config.DefaultCacheTTL, which this package cannot import.
const DefaultCacheTTL = time.Minute

// DefaultNegativeTTL is the Options.NegativeTTL a front end passes unless told
// otherwise: long enough to answer the burst of probes an editor or a shell
// makes for one name, short enough that a name created elsewhere shows up
// within a second. It equals config.DefaultCacheNegativeTTL, the default of
// cache.negative_ttl, which this package cannot import.
const DefaultNegativeTTL = time.Second

// DefaultListConcurrency is the number of background listing refreshes an FS
// built with a zero Options.ListConcurrency runs at once. It equals
// config.DefaultConcurrency, which this package cannot import.
const DefaultListConcurrency = 4

// DefaultUploadConcurrency is the number of uploads an FS built with a zero
// Options.UploadConcurrency sends at once. It equals config.DefaultConcurrency.
const DefaultUploadConcurrency = 4

// ListFunc lists the children of the folder at path in a dataroom.
type ListFunc func(ctx context.Context, dataroomID, path string) ([]service.DataroomNodeInfo, error)

// SessionFunc resolves the cryptographic session of a dataroom.
type SessionFunc func(ctx context.Context, dataroomID string) (*service.DataroomSession, error)

// Options carries the settings of the caches and of an FS. A DataroomCache
// built on its own reads TTL, MaxStale, FetchTimeout and Store only.
//
// The paths an FS takes are absolute, "/" being the dataroom root; they are
// cleaned on the way in (see listingKey), so "/a", "/a/" and "//a" name one
// folder.
type Options struct {
	// TTL is how long a cached entry is served without a refresh; zero means
	// DefaultCacheTTL.
	TTL time.Duration
	// MaxStale is how much longer an expired entry is served while a
	// background refresh replaces it; zero never serves an expired entry.
	MaxStale time.Duration
	// FetchTimeout bounds a fetch shared by several callers; zero means two
	// minutes. Tests shorten it.
	FetchTimeout time.Duration
	// NegativeTTL is how long a name a lookup found missing is answered
	// missing without asking the API again (see FS.Lookup). Unlike TTL, zero
	// is a value: no negative cache. A front end passes DefaultNegativeTTL. A
	// node a lookup found is trusted for TTL.
	NegativeTTL time.Duration
	// NoListingAhead keeps Lookup from fetching, in the background, the
	// listing of a folder whose names are looked up one after the other (see
	// FS.Lookup): every such lookup then asks the API for its name and
	// nothing else. No front end sets it; it is for the tests that count the
	// requests of a mount, where the desktop session of a developer looks
	// names up at the root when it pleases.
	NoListingAhead bool

	// ListConcurrency bounds the background refreshes of expired listings
	// running at once (api.concurrency.list): a client walking a tree served
	// from expired listings would otherwise start one API listing per folder
	// at once. Zero means DefaultListConcurrency.
	ListConcurrency int
	// UploadConcurrency bounds the uploads of the FS sending at once
	// (api.concurrency.upload), whatever the number of files written: every
	// Create and dirty Flush takes a slot for its requests, the chunks of one
	// file being bounded apart by the service. A mount closing thousands of
	// files, or flushing them at unmount, would otherwise send them all at
	// once: the API holds a database connection per request and stalls
	// beyond some sixty. Zero means DefaultUploadConcurrency.
	UploadConcurrency int
	// Store keeps the listings, the results of single lookups and the list of
	// datarooms; nil means a memstore of the FS's own.
	Store metastore.MetaStore
	// Identity is the user's AGE identity, unlocked once at startup: dataroom
	// sessions are resolved from it, without fetching the user key or running
	// scrypt again.
	Identity *age.HybridIdentity
	// HideSymlinks makes Lookup and resolveFolderID treat a symbolic link as a name
	// that does not exist. WebDAV has no symbolic links and sets it; ReadDir
	// returns them either way.
	HideSymlinks bool

	// KeepSealed makes the nodes the FS builds from an answer of the API
	// (listings, lookups by name, the mutations whose route answers the node)
	// carry Node.Sealed, the encrypted fields as the API sent them, for a
	// Store that keeps those in place of the decrypted ones. Off by default:
	// an armored name is about 2.5 KiB per node, held for nothing by a store
	// in memory. A node written through a route that does not answer its
	// encrypted form has none either way: what the store does of such a node
	// is its decision.
	KeepSealed bool

	// SpoolDir is the directory the spool files are created in (see
	// OpenSpool): one file of mode 0600 per file open for writing, as large
	// as its content, removed when it is closed. Empty means the default
	// directory for temporary files (os.TempDir).
	SpoolDir string

	// CopyReplaceRetry and CopyReplaceWait pace Copy onto a destination it
	// just deleted (see Copy); zero means DefaultCopyReplaceRetry and
	// DefaultCopyReplaceWait. Tests shorten them.
	CopyReplaceRetry time.Duration
	CopyReplaceWait  time.Duration

	// Logf receives what the FS has to tell its operator and no caller: a
	// store suspended after a failure and its return, a quota that could not be read, a
	// lock the API did not renew or release. The package never writes to
	// stderr itself; nil discards the messages. The package names a file or
	// a folder by its identifiers (dataroom, node, version) and never by its
	// name or its path: the only string of a caller it prints is the label a
	// front end gives a lock (see LockManager), which is the front end's to
	// choose. The arguments are raw: an error, or that label, which the
	// receiver escapes before printing.
	Logf func(format string, args ...any)

	// FileMode is the mode the front end presents for a file that has none
	// stored, when it is not the API's own default (0644): a chmod to 0644 of
	// such a file is then a change to store, where it otherwise costs
	// nothing. Zero is 0644.
	FileMode os.FileMode

	// List replaces the listing made through the API, session and ETag
	// included, and with it the lookup of a single name, which then reads the
	// listing; Session replaces the resolution of a dataroom session from
	// Identity; ListDatarooms replaces the listing of the user's datarooms
	// through the API. Tests inject fakes through them.
	List          ListFunc
	Session       SessionFunc
	ListDatarooms ListDataroomsFunc

	// ReadChunk replaces the download and decryption of a chunk made through
	// the API, session included. For tests only.
	ReadChunk ReadChunkFunc
	// ChunkSizeOf replaces the request that tells the plaintext size of a
	// chunk without downloading it, session included. An FS given ReadChunk
	// and no ChunkSizeOf has no such request to make, like one whose API
	// predates the route. For tests only.
	ChunkSizeOf ChunkSizeFunc
	// ChunkSize is the plaintext chunk size a File assumes of a version when
	// it fits its number of chunks; zero means service.UploadChunkSize, what
	// this CLI cuts at. It is an assumption, never a fact: the chunk size
	// belongs to each version and is chosen by the client that uploaded it
	// (see file). MaxChunkSize replaces the constant of that name, zero
	// meaning it. Both are for tests only.
	ChunkSize    int64
	MaxChunkSize int64
}

// defaultChunkSize returns ChunkSize, service.UploadChunkSize when unset.
func (o Options) defaultChunkSize() int64 {
	if o.ChunkSize > 0 {
		return o.ChunkSize
	}

	return service.UploadChunkSize
}

// maxChunkSize returns Options.MaxChunkSize, the constant when unset.
func (o Options) maxChunkSize() int64 {
	if o.MaxChunkSize > 0 {
		return o.MaxChunkSize
	}

	return MaxChunkSize
}

// ttl returns the TTL, DefaultCacheTTL when unset.
func (o Options) ttl() time.Duration {
	if o.TTL > 0 {
		return o.TTL
	}

	return DefaultCacheTTL
}

// ListingRetention returns how long after it was fetched a listing may still
// be of use to an FS built with that Options.TTL and Options.MaxStale: served
// for the TTL, served expired for maxStale more, then revalidated by a sweep
// of lookups for a while longer (see FS.Lookup). A store that gives its
// listings a lifetime keeps them that long at least.
func ListingRetention(ttl, maxStale time.Duration) time.Duration {
	ttl = Options{TTL: ttl}.ttl()

	return ttl + max(maxStale, 0) + listingRefreshWindow(ttl)
}

// copyReplacePacing returns CopyReplaceRetry and CopyReplaceWait, their
// defaults when unset.
func (o Options) copyReplacePacing() (retry, wait time.Duration) {
	retry, wait = o.CopyReplaceRetry, o.CopyReplaceWait
	if retry <= 0 {
		retry = DefaultCopyReplaceRetry
	}
	if wait <= 0 {
		wait = DefaultCopyReplaceWait
	}

	return retry, wait
}

// uploadConcurrency returns UploadConcurrency, DefaultUploadConcurrency when
// unset.
func (o Options) uploadConcurrency() int {
	if o.UploadConcurrency > 0 {
		return o.UploadConcurrency
	}

	return DefaultUploadConcurrency
}

// listConcurrency returns ListConcurrency, DefaultListConcurrency when unset.
func (o Options) listConcurrency() int {
	if o.ListConcurrency > 0 {
		return o.ListConcurrency
	}

	return DefaultListConcurrency
}

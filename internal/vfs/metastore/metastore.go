// Package metastore defines where the vfs layer keeps the metadata it caches:
// the MetaStore interface, and the serializable values a store holds.
//
// The package holds data and nothing else. The coordination around it (which
// listing is being fetched, its generation, the refresh slots, the dataroom
// sessions) describes one running process and stays in memory in vfs.FS; a
// store shared by several processes shares the listings, not the
// single-flight.
//
// The data types live here rather than in vfs because vfs imports this
// package: vfs re-exports them as aliases (vfs.Node, vfs.Listing, ...), so a
// front end never needs to import metastore.
//
// It imports the standard library only.
package metastore

import (
	"context"
	"io/fs"
	"time"
)

// NodeType tells a folder, a file and a symbolic link apart. Its values are
// the ones service.DataroomNodeInfo.Type carries.
type NodeType string

// The node types.
const (
	TypeFile    NodeType = "file"
	TypeDir     NodeType = "dir"
	TypeSymlink NodeType = "symlink"
)

// Node is one entry of a folder listing, as the API reported it once
// decrypted. It is a plain value, without pointer or unexported field, so that
// a store can serialize it.
type Node struct {
	ID string
	// ParentID is the ID of the folder holding the node, empty for a child of
	// the dataroom root, which has no node.
	ParentID string
	Name     string // decrypted
	Type     NodeType
	// VersionID and ChunkCount describe a file's current version: what a
	// download needs, without asking the API for the node again.
	VersionID  string
	ChunkCount int
	// Size is a file's size, or the length of a symlink's target.
	Size     int64
	MIMEType string // decrypted; empty for a folder or a symlink
	// Mode is the POSIX mode stored with the node, zero when the API stores
	// none: the front end then applies its own default. ModeSet tells that
	// the API stores Mode even when it is zero (an explicit "0000"); a
	// nonzero Mode is stored whatever ModeSet says. Read both through
	// HasMode.
	Mode    fs.FileMode
	ModeSet bool
	// ModTime is a file's declared modification time, else the creation time
	// of its current version; a folder's creation time. Zero when unknown.
	ModTime time.Time
	// CreatedAt is when the node itself was created, whatever versions it got
	// since. Zero when unknown: an API that reports none, or a node this
	// process created or wrote through a route that does not answer it (see
	// vfs.FS.Mkdir and the uploads of vfs.FS).
	CreatedAt time.Time
	// Target is a symlink's decrypted target, empty otherwise.
	Target string
	// Sealed is what the API sent in place of the decrypted fields, kept only
	// when the caller asked for it (vfs.Options.KeepSealed): a store that must
	// not hold a decrypted name stores it instead of them.
	Sealed Sealed
}

// Sealed holds the encrypted fields of a node exactly as the API answered
// them: nothing here is encrypted by this process for a store. A node whose
// Sealed.Name is empty has no sealed form.
//
// Name, Target and MIMEType each hold one AGE payload for the dataroom session
// key, in one of two forms: armored, the text the API sends
// ("-----BEGIN AGE ENCRYPTED FILE-----" and base64), or binary, the bytes that
// armor encodes, in a string. A store may keep a payload without its armor
// and return it so (redisstore does): the AGE bytes are the same, nothing is
// decrypted nor encrypted on the way. Codec.Open takes both, so does a store
// given back a node it returned.
type Sealed struct {
	// Name is the node's name_enc.
	Name string
	// Target is a symlink's target_enc, empty otherwise.
	Target string
	// MIMETypeID is the row of the dataroom's MIME table a file references
	// (a UUID, not a payload), MIMEType the type_enc of a file that still
	// carries its own.
	MIMETypeID string
	MIMEType   string
}

// ListingMeta is what a store knows of a listing besides its nodes.
type ListingMeta struct {
	// FetchedAt and ETag are Listing.FetchedAt and Listing.ETag.
	FetchedAt time.Time
	ETag      string
}

// Codec is what a store that keeps names out of its keys, or sealed nodes in
// its values, needs from the layer above. vfs.FS implements it and hands
// itself to a store that implements Binder.
type Codec interface {
	// Hash returns the name hash of s in the dataroom (the hash the API
	// already sees for a node name, applied to any string: a name, a path).
	// ok is false when the dataroom's session is not resolved yet: Hash never
	// waits and never reaches the network.
	Hash(dataroomID, s string) (hash string, ok bool)
	// Open fills the decrypted fields of n (Name, Target, MIMEType) from
	// n.Sealed, whose payloads are armored or binary (see Sealed). It never
	// waits and never reaches the network: a MIME type the session does not
	// hold yet is left empty.
	Open(ctx context.Context, dataroomID string, n *Node) error
}

// Binder is implemented by a store that needs a Codec. vfs.New calls Bind
// once, before any other method.
type Binder interface {
	Bind(codec Codec)
}

// leaveSealedKey marks a context whose reads return sealed nodes unopened.
type leaveSealedKey struct{}

// LeaveSealed returns a context that asks the store not to call Codec.Open on
// what it reads with it: a sealed node is returned as it is stored, Name,
// Target and MIMEType empty and Sealed filled (see Node.Unopened), and the
// caller opens it itself. vfs reads the store with its mutex held and opens
// what it read once it has let the mutex go: an AGE decryption per name is
// too long to hold every other operation of the filesystem behind it. A
// listing read so is in no particular order (its names are not known yet). A
// store that keeps no sealed node ignores it.
func LeaveSealed(ctx context.Context) context.Context {
	return context.WithValue(ctx, leaveSealedKey{}, true)
}

// SealedLeft tells whether ctx asks for sealed nodes unopened (see
// LeaveSealed).
func SealedLeft(ctx context.Context) bool {
	left, _ := ctx.Value(leaveSealedKey{}).(bool)

	return left
}

// Unopened tells that n is a sealed node a store returned without opening it
// (see LeaveSealed): its Name, Target and MIMEType are still to be filled by
// Codec.Open. A node always has a name once opened.
func (n *Node) Unopened() bool {
	return n.Name == "" && n.Sealed.Name != ""
}

// HasMode tells that the API stores a mode for n, an explicit 0 included:
// the front end applies its default only when it does not.
func (n *Node) HasMode() bool {
	return n.ModeSet || n.Mode != 0
}

// ListingKey names the listing of one folder. Path is absolute and clean,
// without a trailing slash; "/" is the dataroom root.
type ListingKey struct {
	DataroomID string
	Path       string
}

// Listing is the children of a folder as last fetched.
//
// A Listing given to PutListing is the store's from then on: the caller does
// not modify it afterwards. The Nodes of a Listing returned by GetListing are
// shared with the store and must not be written through. UpsertNode and
// RemoveNode are the only ways to change a stored listing.
type Listing struct {
	Nodes []Node
	// FetchedAt is when the API answered. Whether that makes the listing
	// fresh, stale or expired is the caller's decision, never the store's.
	FetchedAt time.Time
	// ETag is the validator the API answered the listing with, empty when it
	// sent none or when the listing was edited in place since. The store keeps
	// it and does nothing with it.
	ETag string
}

// EntryKey names the result of looking one name up in one folder. ParentPath
// is spelled like ListingKey.Path; Name is the decrypted name looked up.
type EntryKey struct {
	DataroomID string
	ParentPath string
	Name       string
}

// Entry is the result of looking a name up on its own, without listing its
// folder: the node found (positive), or the knowledge that the folder holds
// no such name (negative).
//
// An Entry given to PutEntry is the store's from then on, and the one
// GetEntry returns is shared with the store: neither is modified.
type Entry struct {
	// Node is the node found, nil for a negative entry.
	Node *Node
	// FetchedAt is when the API answered. How long that makes the entry
	// usable is the caller's decision, and differs for a negative one.
	FetchedAt time.Time
}

// DataroomInfo is one dataroom of the user's list.
type DataroomInfo struct {
	ID    string
	Title string
	// DisplayName is the name the dataroom is presented under: its title,
	// with a suffix when several datarooms share it. It is unique in a list.
	DisplayName string
	// Role is the user's role in the dataroom as the list reports it
	// ("viewer", "editor"...), "" when the API does not tell.
	Role string
}

// DataroomList is the datarooms the user can reach, as last fetched.
//
// A DataroomList given to PutDatarooms is the store's from then on, and the
// one GetDatarooms returns is shared with the store: neither is modified.
type DataroomList struct {
	Items []DataroomInfo
	// FetchedAt is when the API answered (see Listing.FetchedAt).
	FetchedAt time.Time
}

// MetaStore keeps folder listings, the results of single-name lookups and the
// list of datarooms. Every method takes a context and returns an error so that
// a store on disk or over the network fits without changing the
// interface; the in-memory one (memstore) never fails.
//
// What an implementation must guarantee:
//
//   - Safe for concurrent use, by several processes when it is shared.
//   - Every write to a listing (PutListing, PutListingIf, RenewListingIf,
//     UpsertNode, RemoveNode, DeleteListing, DeleteSubtree) is atomic and bumps the
//     generation of the listing it touches, in the same step.
//   - A listing keeps the fetch time it was put with: UpsertNode and
//     RemoveNode change neither FetchedAt nor how long the store keeps it,
//     and empty its ETag.
//   - The store may drop what it holds once it is too old to be served (a
//     network store gives its keys a lifetime); it never serves a value as
//     younger than it is. FetchedAt is how old the store knows the value to
//     be, expressed on the reader's clock.
//
// What an implementation outside the process must know:
//
//   - Listings and entries hold decrypted file and folder names, entry keys
//     the names a client looked up: nothing the API ever sees. A store that
//     writes them outside the process takes on their confidentiality, or
//     stores Node.Sealed in their place and names its keys by Codec.Hash.
//
// Deliberately absent: TTLs as a decision (what is fresh is the caller's),
// in-flight fetches (coordination, in vfs.FS), dataroom sessions (key
// material never leaves the process).
type MetaStore interface {
	// GetListing returns the listing stored under key; ok is false when there
	// is none.
	GetListing(ctx context.Context, key ListingKey) (listing *Listing, ok bool, err error)
	// ListingMeta is GetListing without the nodes.
	ListingMeta(ctx context.Context, key ListingKey) (meta ListingMeta, ok bool, err error)
	// GetNode returns the child called name of the listing stored under key.
	// held is false when there is no listing; node is nil when the listing
	// held does not name it.
	GetNode(ctx context.Context, key ListingKey, name string) (node *Node, meta ListingMeta, held bool, err error)
	// GetNamed is GetNode(key, name) and GetEntry of the same folder and name
	// (EntryKey{key.DataroomID, key.Path, name}) answered together, in one
	// round trip for a store over the network: what resolving one name asks.
	// node, meta and held are those of GetNode, entry and hasEntry those of
	// GetEntry; neither half depends on the other.
	GetNamed(ctx context.Context, key ListingKey, name string) (
		node *Node, meta ListingMeta, held bool, entry *Entry, hasEntry bool, err error)

	// Generation returns the generation of the listing of key, whether or not
	// one is stored: a number every write to that listing changes.
	Generation(ctx context.Context, key ListingKey) (gen uint64, err error)
	// PutListing stores listing under key, replacing any previous one.
	PutListing(ctx context.Context, key ListingKey, listing *Listing) error
	// PutListingIf is PutListing when the generation of key is still gen, and
	// nothing otherwise: the listing was asked of the API when the generation
	// was gen, and anything written since is newer than its answer. The
	// comparison and the write are one step.
	PutListingIf(ctx context.Context, key ListingKey, listing *Listing, gen uint64) (stored bool, err error)
	// RenewListingIf gives the listing stored under key the fetch time
	// fetchedAt and the ETag etag, its nodes untouched, when the generation
	// of key is still gen and a listing is held: what PutListingIf would do
	// with the nodes held, without sending them (the API answered that they
	// did not change). The generation is bumped as by PutListingIf. renewed
	// is false, and nothing is written nor bumped, when the generation moved
	// or no listing is held any more: the caller then puts the listing.
	RenewListingIf(ctx context.Context, key ListingKey, etag string, fetchedAt time.Time, gen uint64) (
		renewed bool, err error)
	// UpsertNode replaces the child named like node in the listing stored
	// under key, or adds it. Without a listing nothing is stored. The
	// generation is bumped either way, and returned.
	UpsertNode(ctx context.Context, key ListingKey, node Node) (gen uint64, err error)
	// RemoveNode drops the child called name from the listing stored under
	// key. The generation is bumped whether or not it was there, and returned.
	RemoveNode(ctx context.Context, key ListingKey, name string) (gen uint64, err error)
	// DeleteListing removes the listing stored under key, if any, and bumps
	// its generation.
	DeleteListing(ctx context.Context, key ListingKey) error
	// DeleteSubtree removes the listing of the folder at path in the dataroom
	// and of every folder below it, bumping the generation of each. Below
	// means separated by a slash: "/a" covers "/a/b", never "/ab". "/" covers
	// the whole dataroom.
	DeleteSubtree(ctx context.Context, dataroomID, path string) error

	// GetEntry returns the entry stored under key, positive or negative; ok
	// is false when there is none.
	GetEntry(ctx context.Context, key EntryKey) (entry *Entry, ok bool, err error)
	// PutEntry stores entry under key, replacing any previous one.
	PutEntry(ctx context.Context, key EntryKey, entry *Entry) error
	// PutEntryIf is PutEntry when the generation of the listing of the
	// entry's folder (ListingKey{DataroomID, ParentPath}) is still gen, and
	// nothing otherwise: the name was looked up at the API when the generation
	// was gen, and anything written to the folder since is newer than the
	// answer. The comparison and the write are one step. It does not bump the
	// generation.
	PutEntryIf(ctx context.Context, key EntryKey, entry *Entry, gen uint64) (stored bool, err error)
	// DeleteEntries removes every entry of the folder at parentPath in the
	// dataroom: those whose key carries that ParentPath, and no other.
	DeleteEntries(ctx context.Context, dataroomID, parentPath string) error
	// DeleteEntriesBelow removes the entries of the folder at path in the
	// dataroom and of every folder below it, "below" as in DeleteSubtree. The
	// entry that names the folder itself belongs to its parent and stays.
	DeleteEntriesBelow(ctx context.Context, dataroomID, path string) error

	// GetDatarooms returns the stored list of datarooms; ok is false when
	// there is none.
	GetDatarooms(ctx context.Context) (list *DataroomList, ok bool, err error)
	// PutDatarooms stores list, replacing any previous one.
	PutDatarooms(ctx context.Context, list *DataroomList) error

	// Close releases what the store holds. The store is not used afterwards.
	Close() error
}

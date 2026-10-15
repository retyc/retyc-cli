package vfs

import (
	"path"
	"strings"

	"github.com/retyc/retyc-cli/internal/service"
	"github.com/retyc/retyc-cli/internal/vfs/metastore"
)

// The values a listing is made of are defined in metastore, which this
// package imports to store them; they are re-exported here so that a front
// end deals with vfs alone.
type (
	// Node is one entry of a folder listing (see metastore.Node).
	Node = metastore.Node
	// NodeType tells a folder, a file and a symbolic link apart.
	NodeType = metastore.NodeType
	// Listing is the children of a folder as last fetched.
	Listing = metastore.Listing
	// ListingKey names the listing of one folder of a dataroom.
	ListingKey = metastore.ListingKey
	// Entry is the cached result of looking one name up in one folder.
	Entry = metastore.Entry
	// EntryKey names an Entry.
	EntryKey = metastore.EntryKey
	// DataroomInfo is one dataroom of the user's list.
	DataroomInfo = metastore.DataroomInfo
	// DataroomList is the list of datarooms as last fetched.
	DataroomList = metastore.DataroomList
)

// The node types.
const (
	TypeFile    = metastore.TypeFile
	TypeDir     = metastore.TypeDir
	TypeSymlink = metastore.TypeSymlink
)

// NodeFromInfo converts a node as the service layer reports it, without its
// sealed form (see Options.KeepSealed).
func NodeFromInfo(n service.DataroomNodeInfo) Node {
	return Node{
		ID:         n.ID,
		ParentID:   n.ParentID(),
		CreatedAt:  n.CreatedAt(),
		Name:       n.Name,
		Type:       NodeType(n.Type),
		VersionID:  n.VersionID,
		ChunkCount: n.ChunkCount,
		Size:       n.Size,
		MIMEType:   n.MIMEType,
		Mode:       n.Mode(),
		ModeSet:    n.HasMode(),
		ModTime:    n.ModTime(),
		Target:     n.Target(),
	}
}

// nodeFromInfo is NodeFromInfo for a node the FS is about to cache or return:
// with Options.KeepSealed it carries the encrypted fields the API answered,
// when the route that produced it answers them.
func (fs *FS) nodeFromInfo(n service.DataroomNodeInfo) Node {
	node := NodeFromInfo(n)
	if fs.opts.KeepSealed {
		sealed := n.Sealed()
		node.Sealed = metastore.Sealed{
			Name: sealed.NameEnc, Target: sealed.TargetEnc, MIMETypeID: sealed.MIMETypeID, MIMEType: sealed.TypeEnc,
		}
	}

	return node
}

// nodesFromInfos converts a listing, keeping nil as nil.
func nodesFromInfos(infos []service.DataroomNodeInfo) []Node {
	return convertInfos(infos, NodeFromInfo)
}

// nodesFromInfos is nodesFromInfos with nodeFromInfo.
func (fs *FS) nodesFromInfos(infos []service.DataroomNodeInfo) []Node {
	return convertInfos(infos, fs.nodeFromInfo)
}

func convertInfos(infos []service.DataroomNodeInfo, convert func(service.DataroomNodeInfo) Node) []Node {
	if infos == nil {
		return nil
	}
	nodes := make([]Node, len(infos))
	for i, n := range infos {
		nodes[i] = convert(n)
	}

	return nodes
}

// FindNode returns the node called name in nodes, a listing ReadDir returned.
// It is the lookup of a caller that has just listed a folder and answers for
// its entries one by one (see ReadDir): it reads the slice and nothing else.
func FindNode(nodes []Node, name string) (Node, bool) {
	for _, n := range nodes {
		if n.Name == name {
			return n, true
		}
	}

	return Node{}, false
}

// entryKey names the result of looking name up in the folder at parentPath,
// spelled like the listing of that folder (see listingKey).
func entryKey(dataroomID, parentPath, name string) EntryKey {
	return EntryKey{DataroomID: dataroomID, ParentPath: cleanPath(parentPath), Name: name}
}

// cleanPath returns p as the cache spells a path: absolute and clean, "/" for
// the dataroom root. "/a", "/a/", "/a//", "//a" and "a" are one folder.
func cleanPath(p string) string {
	return path.Clean("/" + p)
}

// listingKey names the listing of the folder at p. It is the only place a
// ListingKey is built from a caller's path: every spelling of a folder then
// reads, edits and drops the same listing.
func listingKey(dataroomID, p string) ListingKey {
	return ListingKey{DataroomID: dataroomID, Path: cleanPath(p)}
}

// joinPath returns the path of the child name of the folder at parent.
func joinPath(parent, name string) string {
	return path.Join(cleanPath(parent), name)
}

// SplitPath returns the parent path and the final component of p.
//
//	"/file.txt"          → ("/", "file.txt")
//	"/folder/sub/f.txt"  → ("/folder/sub", "f.txt")
//	"/"                  → ("/", "")
func SplitPath(p string) (parentPath, name string) {
	p = path.Clean(p)
	idx := strings.LastIndex(p, "/")
	if idx < 0 {
		return "/", p
	}
	if idx == 0 {
		return "/", p[1:]
	}

	return p[:idx], p[idx+1:]
}

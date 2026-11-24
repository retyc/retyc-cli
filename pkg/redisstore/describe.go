package redisstore

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// The kinds of keys, as a key spells them (see the package comment).
const (
	KindListing      = "ls"
	KindEntries      = "e"
	KindGeneration   = "g"
	KindListingToken = "tl"
	KindEntryToken   = "te"
)

// ErrUnreadable is what Describe answers for a value the store would read as
// absent. Its message tells the size and the first byte of the value, never
// its content.
var ErrUnreadable = errors.New("redisstore: unreadable value")

// Key is a key of the store, cut into its parts.
type Key struct {
	Prefix     string `json:"prefix"`
	DataroomID string `json:"dataroom_id"`
	Kind       string `json:"kind"`
	Hash       string `json:"hash"`
}

// ParseKey cuts a key of the store; ok is false for a key of another layout.
func ParseKey(key string) (Key, bool) {
	prefix, rest, ok := strings.Cut(key, ":"+schema+":{")
	if !ok {
		return Key{}, false
	}
	dataroomID, rest, ok := strings.Cut(rest, "}:")
	if !ok {
		return Key{}, false
	}
	kind, h, ok := strings.Cut(rest, ":")
	switch kind {
	case KindListing, KindEntries, KindGeneration, KindListingToken, KindEntryToken:
	default:
		ok = false
	}
	if !ok || prefix == "" || dataroomID == "" || h == "" {
		return Key{}, false
	}

	return Key{Prefix: prefix, DataroomID: dataroomID, Kind: kind, Hash: h}, true
}

// globEscaper makes a string match itself in a Redis pattern.
var globEscaper = strings.NewReplacer(`\`, `\\`, `*`, `\*`, `?`, `\?`, `[`, `\[`, `]`, `\]`)

// KeyPattern is the pattern (SCAN MATCH) of the keys under prefix,
// DefaultPrefix when empty; an empty dataroomID or kind matches any.
func KeyPattern(prefix, dataroomID, kind string) string {
	if prefix == "" {
		prefix = DefaultPrefix
	}
	dataroomID, kind = globEscaper.Replace(dataroomID), globEscaper.Replace(kind)
	if dataroomID == "" {
		dataroomID = "*"
	}
	if kind == "" {
		kind = "*"
	}

	return globEscaper.Replace(prefix) + ":" + schema + ":{" + dataroomID + "}:" + kind + ":*"
}

// NodeDescription is a stored node, for a person to read. A sealed node is
// described without being opened: each of its payloads is told by its size.
type NodeDescription struct {
	Sealed     bool   `json:"sealed"`
	ID         string `json:"id"`
	ParentID   string `json:"parent_id,omitempty"`
	Type       string `json:"type,omitempty"`
	Name       string `json:"name"`
	Target     string `json:"target,omitempty"`
	MIMEType   string `json:"mime,omitempty"`
	MIMETypeID string `json:"mime_id,omitempty"`
	VersionID  string `json:"version_id,omitempty"`
	ChunkCount int    `json:"chunks,omitempty"`
	Size       int64  `json:"size"`
	Mode       string `json:"mode,omitempty"`
	ModTime    string `json:"mtime,omitempty"`
	CreatedAt  string `json:"ctime,omitempty"`
	// Bytes is the size of the node in the value, Unread how many of them
	// follow the last field this version knows: fields of a later one.
	Bytes  int `json:"bytes"`
	Unread int `json:"unread_bytes,omitempty"`
}

// EntryDescription is a stored entry. LifeMS is the lifetime it was stored
// with; what is left of it is the lifetime of its field (HPTTL).
type EntryDescription struct {
	Negative bool             `json:"negative"`
	LifeMS   int64            `json:"life_ms"`
	Node     *NodeDescription `json:"node,omitempty"`
	Bytes    int              `json:"bytes"`
}

// MetaDescription is the reserved field of a listing.
type MetaDescription struct {
	FormatVersion int   `json:"format_version"`
	LifeMS        int64 `json:"life_ms"`
}

// TokensDescription is the field "t" of a listing or of an entries hash: the
// tokens of each folder from the root down to its own, as they were when it
// was written. The value is served only while they all still are.
type TokensDescription struct {
	Tokens []string `json:"tokens"`
}

func describeTokens(value []byte) *TokensDescription {
	return &TokensDescription{Tokens: strings.Split(string(value), ",")}
}

// unreadable is ErrUnreadable for a value of kind what.
func unreadable(what string, value []byte) error {
	switch {
	case len(value) == 0:
		return fmt.Errorf("%w: an empty %s", ErrUnreadable, what)
	case value[0] != wireVersion:
		return fmt.Errorf("%w: %s of %d bytes whose first byte is 0x%02x, not the format version %d",
			ErrUnreadable, what, len(value), value[0], wireVersion)
	default:
		return fmt.Errorf("%w: %s of %d bytes of format version %d that does not parse",
			ErrUnreadable, what, len(value), wireVersion)
	}
}

func payloadSize(p string) string {
	if p == "" {
		return ""
	}

	return fmt.Sprintf("<AGE payload, %d bytes>", len(p))
}

// timeText is t in RFC 3339, or in Unix seconds for a year that form does
// not take; empty for no time.
func timeText(t time.Time) string {
	switch {
	case t.IsZero():
		return ""
	case t.Year() < 0 || t.Year() > 9999:
		return fmt.Sprintf("unix %d.%09d", t.Unix(), t.Nanosecond())
	default:
		return t.Format(time.RFC3339Nano)
	}
}

// describeNode reads the fields of a node off r as the store does.
func describeNode(r *reader) (*NodeDescription, bool) {
	size := len(r.s)
	n, sealed, ok := r.node()
	if !ok {
		return nil, false
	}
	d := &NodeDescription{
		Sealed:     sealed,
		ID:         n.ID,
		ParentID:   n.ParentID,
		Type:       string(n.Type),
		Name:       n.Name,
		Target:     n.Target,
		MIMEType:   n.MIMEType,
		VersionID:  n.VersionID,
		ChunkCount: n.ChunkCount,
		Size:       n.Size,
		ModTime:    timeText(n.ModTime),
		CreatedAt:  timeText(n.CreatedAt),
		Bytes:      size,
		Unread:     len(r.s),
	}
	if n.HasMode() {
		d.Mode = fmt.Sprintf("0%03o", uint64(n.Mode))
	}
	if sealed {
		d.MIMETypeID = n.Sealed.MIMETypeID
		d.Name, d.Target = payloadSize(n.Sealed.Name), payloadSize(n.Sealed.Target)
		d.MIMEType = payloadSize(n.Sealed.MIMEType)
	}

	return d, true
}

// Describe decodes what a key of the given kind holds, with the decoder the
// store reads with and without a codec: nothing is decrypted, a sealed name
// is told by its size. field is the field of the hash; value its value, or
// the value of the key for KindGeneration and the tokens. It answers
//
//   - KindListing: a *MetaDescription for the field "m", the ETag (a string)
//     for the field "etag", a *TokensDescription for the field "t", a
//     *NodeDescription for the field of a child;
//   - KindEntries: a *TokensDescription for the field "t", an
//     *EntryDescription for any other;
//   - KindGeneration: the stored number, a uint64 (a random start plus the
//     writes since; not what vfs is given, which adds the tokens to it);
//   - KindListingToken, KindEntryToken: the token, a string.
//
// all of which encoding/json prints. A value the store would read as absent
// is an error that wraps ErrUnreadable.
func Describe(kind, field string, value []byte) (any, error) {
	switch kind {
	case KindListing:
		switch {
		case field == metaField:
			meta, ok := decodeMeta(string(value))
			if !ok {
				return nil, fmt.Errorf("%w: listing meta of %d bytes", ErrUnreadable, len(value))
			}

			return &MetaDescription{FormatVersion: meta.V, LifeMS: meta.LifeMS}, nil
		case field == etagField:
			return string(value), nil
		case field == tokensField:
			return describeTokens(value), nil
		case strings.HasPrefix(field, nodePrefix):
			r, ok := unframe(string(value))
			if !ok {
				return nil, unreadable("node", value)
			}
			d, ok := describeNode(&r)
			if !ok {
				return nil, unreadable("node", value)
			}

			return d, nil
		default:
			return nil, fmt.Errorf("redisstore: a listing has no field of that name (%d bytes)", len(field))
		}
	case KindEntries:
		if field == tokensField {
			return describeTokens(value), nil
		}
		d, err := describeEntry(value)
		if err != nil {
			return nil, err
		}

		return d, nil
	case KindGeneration:
		gen, err := strconv.ParseUint(string(value), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%w: generation of %d bytes", ErrUnreadable, len(value))
		}

		return gen, nil
	case KindListingToken, KindEntryToken:
		return string(value), nil
	default:
		return nil, fmt.Errorf("redisstore: nothing to describe in a key of kind %q", kind)
	}
}

func describeEntry(value []byte) (*EntryDescription, error) {
	lifeMS, node, _, ok := decodeEntry(string(value))
	if !ok {
		return nil, unreadable("entry", value)
	}
	d := &EntryDescription{Negative: node == nil, LifeMS: lifeMS, Bytes: len(value)}
	if node == nil {
		return d, nil
	}
	// Read once more for the description of the node: its size and what is
	// left unread are the reader's.
	r, _ := unframe(string(value))
	r.byte()
	r.uvarint()
	fields := r.sub()
	if d.Node, ok = describeNode(&fields); !ok {
		return nil, unreadable("entry", value)
	}

	return d, nil
}

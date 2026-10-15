package redisstore

import (
	"context"
	"encoding/binary"
	"io"
	"io/fs"
	"math"
	"strconv"
	"strings"
	"time"

	"filippo.io/age/armor"

	"github.com/retyc/retyc-cli/internal/vfs/metastore"
)

// The values of a listing's children and of the entries are binary, written
// here by hand with encoding/binary. A value is a frame:
//
//	byte      wireVersion
//	uvarint   L, the length of the fields
//	L bytes   the fields, in the fixed order below
//
// and nothing after it. The fields of a node:
//
//	byte      type: 0 none, 1 file, 2 dir, 3 symlink
//	byte      flags: 1 sealed, 2 has a modification time, 4 has a creation time,
//	          8 the mode is stored even when it is 0 (Node.ModeSet)
//	ident     ID
//	ident     parent ID
//	ident     version ID
//	uvarint   chunk count
//	uvarint   size
//	uvarint   mode (fs.FileMode, 32 bits): stored when nonzero or flagged
//	time      modification time, when its flag is set
//	time      creation time, when its flag is set
//	clear:    string name, string target, string MIME type
//	sealed:   ident MIME type ID, then the AGE payloads of the name, of the
//	          target and of the MIME type, three strings holding the binary
//	          payload as it is (see unarmor)
//
// The fields of an entry:
//
//	byte      0 negative, 1 positive
//	uvarint   the lifetime the entry was stored with, in ms
//	positive: uvarint Ln, then the Ln bytes of the fields of its node
//
// uvarint is binary.AppendUvarint. A string is a uvarint length and its
// bytes. An ident is a zero byte and 16 bytes for a canonical UUID (36
// characters, lower case), otherwise a uvarint of the length plus one and
// the bytes: any string comes back as it was written. A time is a varint of
// Unix seconds and a uvarint of nanoseconds (below 1e9), read back in UTC:
// the instant vfs holds, to the nanosecond, at any date; a zero time has no
// flag and no bytes. Chunk count and size are the two's complement of their
// signed value.
//
// How the format grows. A field is added at the end of the fields it belongs
// to (of a node, of an entry) and nowhere else, optionally announced by a
// flag bit that is free today; a reader stops after the last field it knows
// and ignores what is left of the L (or Ln) bytes, and ignores the flag bits
// it does not know. That is why each block of fields carries its length,
// the node of an entry included. Such a field must be one an older reader
// may miss: that reader writes the node back without it. Anything else (a
// field removed, reordered or given another meaning, a new type byte that an
// older reader must not take for absent) is another wireVersion: a value of
// another version is read as absent, never as an error, since a newer
// process may share the Redis. So is any value that does not parse: cut
// short, a length beyond what is left, a varint that does not end, a type or
// a kind this version does not know, bytes after the frame.
//
// Describe (describe.go) decodes a value for a person;
// scripts/redis-cache-dump prints a whole cache with it.

// wireVersion is the format of the values, their first byte.
const wireVersion = 1

// The type byte of a node.
const (
	wireTypeNone byte = iota
	wireTypeFile
	wireTypeDir
	wireTypeSymlink
)

// The flags of a node.
const (
	flagSealed byte = 1 << iota
	flagModTime
	flagCreatedAt
	// flagModeSet came after the first values of wireVersion 1, by the rule
	// above: a value without it whose mode is nonzero was written before and
	// carries a stored mode (metastore.Node.HasMode). A reader that predates
	// it reads an explicit 0 as no mode, the default it always presented.
	flagModeSet
)

// The kind byte of an entry.
const (
	entryNegative byte = iota
	entryPositive
)

// uuidLen is the length of a UUID in its canonical text form.
const uuidLen = 36

const hexDigits = "0123456789abcdef"

// wireMeta is the reserved field of a listing, written "<V>:<LifeMS>" and not
// as JSON: the scripts that edit a listing tell with a pattern whether this
// version reads it. LifeMS is the lifetime the listing was stored with: with
// what Redis says is left of it, its age. The ETag is a field of its own,
// which an edit removes.
type wireMeta struct {
	V      int
	LifeMS int64
}

// unarmor returns the AGE payload p without its armor: the bytes the armor
// encodes, nothing decrypted and nothing encrypted. A payload that is not
// armored is binary already (a node read from Redis and written again) and
// returned as it is. ok is false for an armor that does not decode.
func unarmor(p string) (bin string, ok bool) {
	if !strings.HasPrefix(strings.TrimSpace(p), armor.Header) {
		return p, true
	}
	raw, err := io.ReadAll(armor.NewReader(strings.NewReader(p)))
	if err != nil || len(raw) == 0 {
		return "", false
	}

	return string(raw), true
}

// typeByte is the type byte of t; ok is false for a type this format has no
// byte for.
func typeByte(t metastore.NodeType) (byte, bool) {
	switch t {
	case "":
		return wireTypeNone, true
	case metastore.TypeFile:
		return wireTypeFile, true
	case metastore.TypeDir:
		return wireTypeDir, true
	case metastore.TypeSymlink:
		return wireTypeSymlink, true
	default:
		return 0, false
	}
}

func typeOf(b byte) (metastore.NodeType, bool) {
	switch b {
	case wireTypeNone:
		return "", true
	case wireTypeFile:
		return metastore.TypeFile, true
	case wireTypeDir:
		return metastore.TypeDir, true
	case wireTypeSymlink:
		return metastore.TypeSymlink, true
	default:
		return "", false
	}
}

func appendString(b []byte, s string) []byte {
	return append(binary.AppendUvarint(b, uint64(len(s))), s...)
}

// unhex is the value of a lower case hexadecimal digit, ok false for any
// other byte.
func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	default:
		return 0, false
	}
}

// appendIdent appends an identifier: 16 bytes after a zero byte when it is a
// canonical UUID, the string itself otherwise.
func appendIdent(b []byte, id string) []byte {
	if len(id) != uuidLen {
		return appendString1(b, id)
	}
	var raw [16]byte
	for i, j := 0, 0; i < uuidLen; {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if id[i] != '-' {
				return appendString1(b, id)
			}
			i++

			continue
		}
		hi, ok1 := unhex(id[i])
		lo, ok2 := unhex(id[i+1])
		if !ok1 || !ok2 {
			return appendString1(b, id)
		}
		raw[j] = hi<<4 | lo
		i, j = i+2, j+1
	}

	return append(append(b, 0), raw[:]...)
}

// appendString1 is the form of an identifier that is not a UUID: its length
// plus one, zero announcing a UUID.
func appendString1(b []byte, id string) []byte {
	return append(binary.AppendUvarint(b, uint64(len(id))+1), id...)
}

func appendTime(b []byte, t time.Time) []byte {
	return binary.AppendUvarint(binary.AppendVarint(b, t.Unix()), uint64(t.Nanosecond())) // #nosec G115 -- in [0, 1e9)
}

// appendNode appends the fields of n; ok is false when this store may not
// write it: a type the format does not know, or high confidentiality and no
// sealed name to store in place of the decrypted one, a name or a target
// whose armor does not decode being no sealed form. The MIME type is
// cosmetic: one whose armor does not decode is left out.
func (s *Store) appendNode(b []byte, n *metastore.Node) ([]byte, bool) {
	kind, ok := typeByte(n.Type)
	if !ok {
		return nil, false
	}
	var name, target, mime string
	var flags byte
	var sealed metastore.Sealed
	if n.Sealed != nil {
		sealed = *n.Sealed
	}
	if s.opts.HighConfidentiality {
		flags |= flagSealed
		if name, ok = unarmor(sealed.Name); !ok || name == "" {
			return nil, false
		}
		if target, ok = unarmor(sealed.Target); !ok {
			return nil, false
		}
		if mime, ok = unarmor(sealed.MIMEType); !ok {
			mime = ""
		}
	} else {
		// A node without a name is refused at the read, which then drops
		// the whole listing: it is not written either.
		if n.Name == "" {
			return nil, false
		}
		name, target, mime = n.Name, n.Target, n.MIMEType
	}
	if !n.ModTime.IsZero() {
		flags |= flagModTime
	}
	if !n.CreatedAt.IsZero() {
		flags |= flagCreatedAt
	}
	if n.ModeSet {
		flags |= flagModeSet
	}
	b = append(b, kind, flags)
	b = appendIdent(b, n.ID)
	b = appendIdent(b, n.ParentID)
	b = appendIdent(b, n.VersionID)
	b = binary.AppendUvarint(b, uint64(int64(n.ChunkCount))) // #nosec G115 -- two's complement, read back as it is
	b = binary.AppendUvarint(b, uint64(n.Size))              // #nosec G115 -- two's complement, read back as it is
	b = binary.AppendUvarint(b, uint64(n.Mode))
	if flags&flagModTime != 0 {
		b = appendTime(b, n.ModTime)
	}
	if flags&flagCreatedAt != 0 {
		b = appendTime(b, n.CreatedAt)
	}
	if flags&flagSealed != 0 {
		b = appendIdent(b, sealed.MIMETypeID)
	}
	b = appendString(b, name)
	b = appendString(b, target)

	return appendString(b, mime), true
}

// frame is the value that holds fields: the version, their length, then
// them.
func frame(fields []byte) string {
	var head [1 + binary.MaxVarintLen64]byte
	head[0] = wireVersion
	n := 1 + binary.PutUvarint(head[1:], uint64(len(fields)))

	return string(head[:n]) + string(fields)
}

// encodeNode is the value of a node; ok as appendNode tells.
func (s *Store) encodeNode(n *metastore.Node) (string, bool) {
	fields, ok := s.appendNode(make([]byte, 0, 192), n)
	if !ok {
		return "", false
	}

	return frame(fields), true
}

// encodeEntry is the value of an entry stored with the lifetime life, node
// being nil for a negative one; ok as appendNode tells.
func (s *Store) encodeEntry(life time.Duration, node *metastore.Node) (string, bool) {
	b := make([]byte, 0, 192)
	lifeMS := uint64(life.Milliseconds()) // #nosec G115 -- positive, see entryValue
	if node == nil {
		return frame(binary.AppendUvarint(append(b, entryNegative), lifeMS)), true
	}
	fields, ok := s.appendNode(nil, node)
	if !ok {
		return "", false
	}
	b = binary.AppendUvarint(append(b, entryPositive), lifeMS)
	b = binary.AppendUvarint(b, uint64(len(fields)))

	return frame(append(b, fields...)), true
}

// reader reads fields off a value. Nothing it reads is trusted: a length is
// compared with what is left before anything is sliced or allocated, and the
// first thing that does not parse sets bad, after which every read answers
// zero. The caller looks at bad once, at the end.
type reader struct {
	s   string
	bad bool
}

func (r *reader) fail() {
	r.s, r.bad = "", true
}

func (r *reader) byte() byte {
	if len(r.s) == 0 {
		r.fail()

		return 0
	}
	c := r.s[0]
	r.s = r.s[1:]

	return c
}

// uvarint is binary.Uvarint on a string: ten bytes at most, the tenth
// holding one bit.
func (r *reader) uvarint() uint64 {
	var x uint64
	for i := 0; i < len(r.s) && i < binary.MaxVarintLen64; i++ {
		c := r.s[i]
		if c < 0x80 {
			if i == binary.MaxVarintLen64-1 && c > 1 {
				break
			}
			r.s = r.s[i+1:]

			return x | uint64(c)<<(7*uint(i)) // #nosec G115 -- i < 10
		}
		x |= uint64(c&0x7f) << (7 * uint(i)) // #nosec G115 -- i < 10
	}
	r.fail()

	return 0
}

func (r *reader) varint() int64 {
	ux := r.uvarint()
	x := int64(ux >> 1) // #nosec G115 -- zigzag, as binary.Varint
	if ux&1 != 0 {
		x = ^x
	}

	return x
}

// take returns the next n bytes, a substring of the value: nothing is
// allocated for a length read from Redis.
func (r *reader) take(n uint64) string {
	if n > uint64(len(r.s)) {
		r.fail()

		return ""
	}
	out := r.s[:n]
	r.s = r.s[n:]

	return out
}

// str reads a string and copies it: a short field does not keep the whole
// value alive.
func (r *reader) str() string {
	return strings.Clone(r.take(r.uvarint()))
}

// sub returns a reader of a block of fields that carries its length. What
// the block holds after the fields its reader knows is skipped with it.
func (r *reader) sub() reader {
	block := r.take(r.uvarint())

	return reader{s: block, bad: r.bad}
}

func (r *reader) ident() string {
	n := r.uvarint()
	if n != 0 {
		return strings.Clone(r.take(n - 1))
	}
	raw := r.take(16)
	if r.bad {
		return ""
	}
	var out [uuidLen]byte
	for i, j := 0, 0; j < len(raw); j++ {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			out[i] = '-'
			i++
		}
		out[i], out[i+1] = hexDigits[raw[j]>>4], hexDigits[raw[j]&0xf]
		i += 2
	}

	return string(out[:])
}

func (r *reader) time() time.Time {
	sec, nsec := r.varint(), r.uvarint()
	if r.bad || nsec >= uint64(time.Second) {
		r.fail()

		return time.Time{}
	}

	return time.Unix(sec, int64(nsec)).UTC() // #nosec G115 -- below 1e9
}

// node reads the fields of a node. sealed tells that its name is still to be
// opened, its sealed fields being binary AGE payloads; ok is false for
// fields that do not parse or that carry no name. What follows the last
// field is left unread: fields a later writer added.
func (r *reader) node() (n metastore.Node, sealed, ok bool) {
	kind, typeOK := typeOf(r.byte())
	flags := r.byte()
	sealed = flags&flagSealed != 0
	n = metastore.Node{Type: kind, ID: r.ident(), ParentID: r.ident(), VersionID: r.ident()}
	// Chunk count and size are the two's complement of what was written.
	chunks, size, mode := int64(r.uvarint()), int64(r.uvarint()), r.uvarint() // #nosec G115
	if !typeOK || int64(int(chunks)) != chunks || mode > math.MaxUint32 {
		return metastore.Node{}, false, false
	}
	n.ChunkCount, n.Size, n.Mode = int(chunks), size, fs.FileMode(mode)
	n.ModeSet = flags&flagModeSet != 0
	if flags&flagModTime != 0 {
		n.ModTime = r.time()
	}
	if flags&flagCreatedAt != 0 {
		n.CreatedAt = r.time()
	}
	if sealed {
		// The payloads are not copied: they are most of the value.
		s := &metastore.Sealed{MIMETypeID: r.ident()}
		s.Name, s.Target, s.MIMEType = r.take(r.uvarint()), r.take(r.uvarint()), r.take(r.uvarint())
		n.Sealed = s
	} else {
		n.Name, n.Target, n.MIMEType = r.str(), r.str(), r.str()
	}
	if r.bad || (n.Name == "" && (n.Sealed == nil || n.Sealed.Name == "")) {
		return metastore.Node{}, false, false
	}

	return n, sealed, true
}

// unframe returns a reader of the fields of a value; ok is false for another
// version and for a frame that is not exactly the value.
func unframe(value string) (reader, bool) {
	if len(value) == 0 || value[0] != wireVersion {
		return reader{}, false
	}
	r := reader{s: value[1:]}
	fields := r.sub()

	return fields, !fields.bad && len(r.s) == 0
}

// decodeNode reads the value of a node, see reader.node.
func decodeNode(value string) (n metastore.Node, sealed, ok bool) {
	r, ok := unframe(value)
	if !ok {
		return n, false, false
	}

	return r.node()
}

// decodeEntry reads the value of an entry: the lifetime it was stored with
// and its node, nil for a negative one.
func decodeEntry(value string) (lifeMS int64, node *metastore.Node, sealed, ok bool) {
	r, ok := unframe(value)
	if !ok {
		return 0, nil, false, false
	}
	kind, life := r.byte(), r.uvarint()
	if r.bad || life == 0 || life > math.MaxInt64 {
		return 0, nil, false, false
	}
	switch kind {
	case entryNegative:
		return int64(life), nil, false, true
	case entryPositive:
		fields := r.sub()
		n, sealed, ok := fields.node()
		if !ok {
			return 0, nil, false, false
		}

		return int64(life), &n, sealed, true
	default:
		return 0, nil, false, false
	}
}

// open has the codec fill the decrypted fields of a sealed node. A node that
// cannot be opened (an error of the codec, the context's end included, or a
// name still empty) is unreadable: the caller treats what holds it as
// absent. With a context made by metastore.LeaveSealed the node is left as
// it is (see metastore.Node.Unopened): the caller opens it, and treats it as
// absent should it not open.
func (h hasher) open(ctx context.Context, n *metastore.Node) bool {
	if h.codec == nil {
		return false
	}
	if metastore.SealedLeft(ctx) {
		return true
	}
	if err := h.codec.Open(ctx, h.dataroomID, n); err != nil {
		return false
	}

	return n.Name != ""
}

// decodeMeta reads the reserved field of a listing. It accepts what the
// scripts accept (lua/upsert_node.lua) and nothing else.
func decodeMeta(raw string) (wireMeta, bool) {
	version, life, ok := strings.Cut(raw, ":")
	if !ok || version != strconv.Itoa(wireVersion) || life == "" || strings.Trim(life, "0123456789") != "" {
		return wireMeta{}, false
	}
	ms, err := strconv.ParseInt(life, 10, 64)
	if err != nil || ms <= 0 {
		return wireMeta{}, false
	}

	return wireMeta{V: wireVersion, LifeMS: ms}, true
}

func encodeMeta(life time.Duration) string {
	return strconv.Itoa(wireVersion) + ":" + strconv.FormatInt(life.Milliseconds(), 10)
}

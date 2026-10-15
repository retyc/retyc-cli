package redisstore

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io/fs"
	"math"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"filippo.io/age/armor"

	"github.com/retyc/retyc-cli/internal/vfs/metastore"
)

var (
	clearWire  = &Store{}
	sealedWire = &Store{opts: Options{HighConfidentiality: true}}
)

// wireNodes are nodes of every shape the format has a case for, with their
// decrypted fields and a (fake, binary) sealed form.
func wireNodes() map[string]metastore.Node {
	const id, parent, version = "0b1f0c5e-1a2b-4c3d-8e9f-0123456789ab", "ffffffff-ffff-4fff-bfff-ffffffffffff",
		"00000000-0000-0000-0000-000000000000"
	sealed := &metastore.Sealed{Name: "age-encryption.org/v1\nname\x00\xff", MIMETypeID: parent}

	return map[string]metastore.Node{
		"file": {
			ID: id, ParentID: parent, Name: "report.pdf", Type: metastore.TypeFile, VersionID: version,
			ChunkCount: 3, Size: 20 << 20, MIMEType: "application/pdf", Mode: 0o644,
			ModTime:   time.Date(2026, 10, 13, 8, 30, 12, 123456789, time.UTC),
			CreatedAt: time.Date(2026, 10, 1, 0, 0, 0, 123456000, time.UTC),
			Sealed:    sealed,
		},
		"folder at the root": {ID: id, Name: "dir", Type: metastore.TypeDir, Sealed: sealed},
		"explicit mode 0":    {ID: id, Name: "locked", Type: metastore.TypeFile, ModeSet: true, Sealed: sealed},
		"setuid alone": {
			ID: id, Name: "s", Type: metastore.TypeFile, Mode: fs.ModeSetuid, ModeSet: true, Sealed: sealed,
		},
		"symlink": {
			ID: id, ParentID: parent, Name: "link", Type: metastore.TypeSymlink, Target: "../a/b", Size: 6,
			Sealed: &metastore.Sealed{Name: "n", Target: "t", MIMEType: "m"},
		},
		"identifiers that are not canonical UUIDs": {
			ID: "n1", ParentID: strings.ToUpper(parent), VersionID: "0b1f0c5e-1a2b-4c3d-8e9f-0123456789a", Name: "x",
			Type: metastore.TypeFile, Sealed: &metastore.Sealed{Name: "n", MIMETypeID: "0b1f0c5e_1a2b-4c3d-8e9f-0123456789ab"},
		},
		"no type, odd numbers, names with zero bytes": {
			ID: "", Name: "a\x00b\nc é", MIMEType: "\x00", Size: -1, ChunkCount: -2, Mode: fs.ModeDir | fs.ModeSetuid | 0o777,
			ModTime: time.Unix(-1, 999999999).UTC(), CreatedAt: time.Date(9999, 12, 31, 23, 59, 59, 1, time.UTC),
			Sealed: &metastore.Sealed{Name: "\x00"},
		},
		"dates no calendar text holds": {
			ID: id, Name: "far", Type: metastore.TypeFile,
			ModTime: time.Unix(1<<40, 5).UTC(), CreatedAt: time.Unix(math.MinInt64/2, 0).UTC(), Sealed: sealed,
		},
		"dates far from now": {
			ID: id, Name: "old", Type: metastore.TypeFile, Size: math.MaxInt64,
			ModTime: time.Date(1, 1, 1, 0, 0, 0, 1, time.UTC), CreatedAt: time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC),
			Sealed: sealed,
		},
	}
}

// What is written is read back exactly, clear and sealed, as a node and as
// the node of an entry.
func TestWire_RoundTrip(t *testing.T) {
	for name, n := range wireNodes() {
		clear := n
		clear.Sealed = nil
		sealed := metastore.Node{
			ID: n.ID, ParentID: n.ParentID, Type: n.Type, VersionID: n.VersionID, ChunkCount: n.ChunkCount,
			Size: n.Size, Mode: n.Mode, ModeSet: n.ModeSet, ModTime: n.ModTime, CreatedAt: n.CreatedAt, Sealed: n.Sealed,
		}
		for mode, c := range map[string]struct {
			store *Store
			want  metastore.Node
		}{"clear": {clearWire, clear}, "sealed": {sealedWire, sealed}} {
			value, ok := c.store.encodeNode(&n)
			if !ok {
				t.Fatalf("%s, %s: not encoded", name, mode)
			}
			got, isSealed, ok := decodeNode(value)
			if !ok || isSealed != (mode == "sealed") || !reflect.DeepEqual(got, c.want) {
				t.Errorf("%s, %s: ok=%v sealed=%v\n got %+v\nwant %+v", name, mode, ok, isSealed, got, c.want)
			}
			entry, ok := c.store.encodeEntry(90*time.Second, &n)
			if !ok {
				t.Fatalf("%s, %s: entry not encoded", name, mode)
			}
			life, node, isSealed, ok := decodeEntry(entry)
			if !ok || life != 90000 || node == nil || isSealed != (mode == "sealed") || !reflect.DeepEqual(*node, c.want) {
				t.Errorf("%s, %s: entry read as %d, %+v, sealed=%v, ok=%v", name, mode, life, node, isSealed, ok)
			}
			if mode == "sealed" && len(n.Name) > 2 && (strings.Contains(value, n.Name) || strings.Contains(entry, n.Name)) {
				t.Errorf("%s: a sealed value holds the decrypted name", name)
			}
		}
	}
	negative, ok := clearWire.encodeEntry(time.Second, nil)
	if life, node, sealed, read := decodeEntry(negative); !ok || !read || life != 1000 || node != nil || sealed {
		t.Errorf("negative entry: %d, %v, %v, %v", life, node, sealed, read)
	}
	if len(negative) != 5 {
		t.Errorf("a negative entry is %d bytes", len(negative))
	}
}

// A time in another zone, or with a monotonic reading, is stored as its
// instant; the sizes the format was chosen for hold.
func TestWire_TimesAndSize(t *testing.T) {
	n := wireNodes()["file"]
	n.Sealed = nil
	n.ModTime = time.Now().In(time.FixedZone("x", 3600))
	value, _ := clearWire.encodeNode(&n)
	got, _, ok := decodeNode(value)
	if !ok || !got.ModTime.Equal(n.ModTime) || got.ModTime.Location() != time.UTC {
		t.Errorf("ModTime %v read as %v", n.ModTime, got.ModTime)
	}
	raw, err := json.Marshal(n)
	must(t, err)
	// Three UUIDs (51 bytes), two dates, a name and a MIME type of 25 bytes.
	if len(value) > 110 || len(value)*3 > len(raw) {
		t.Errorf("a file is %d bytes, %d as JSON", len(value), len(raw))
	}
}

// What this store may not write is refused, not written in another form.
func TestWire_NotEncoded(t *testing.T) {
	odd := metastore.Node{ID: "i", Name: "x", Type: "socket"}
	if _, ok := clearWire.encodeNode(&odd); ok {
		t.Error("a node of an unknown type was encoded")
	}
	if _, ok := clearWire.encodeEntry(time.Second, &odd); ok {
		t.Error("an entry whose node has an unknown type was encoded")
	}
	if _, ok := sealedWire.encodeNode(&metastore.Node{ID: "i", Name: "x"}); ok {
		t.Error("a node without sealed name was encoded in high confidentiality")
	}
	broken := &metastore.Sealed{Name: armor.Header + "\n!"}
	if _, ok := sealedWire.encodeNode(&metastore.Node{ID: "i", Sealed: broken}); ok {
		t.Error("a sealed name whose armor does not decode was encoded")
	}
}

// The rule of evolution: bytes after the last known field of a block, and
// flag bits this version does not know, are ignored; another version byte,
// another type or another entry kind is absent.
func TestWire_Evolution(t *testing.T) {
	n := wireNodes()["file"]
	want := n
	want.Sealed = nil
	value, _ := clearWire.encodeNode(&n)
	fields := []byte(fieldsOf(t, value))

	later := append(append([]byte{}, fields...), "a field of a later version"...)
	later[1] |= 0x80 | 0x40
	if got, sealed, ok := decodeNode(frame(later)); !ok || sealed || !reflect.DeepEqual(got, want) {
		t.Errorf("node with a later field and later flags: ok=%v sealed=%v %+v", ok, sealed, got)
	}
	// In an entry, after the node inside its block and after the block.
	b := binary.AppendUvarint(binary.AppendUvarint([]byte{entryPositive}, 5000), uint64(len(later)))
	b = append(append(b, later...), "a later field of the entry"...)
	if life, node, _, ok := decodeEntry(frame(b)); !ok || life != 5000 || node == nil || !reflect.DeepEqual(*node, want) {
		t.Errorf("entry with later fields: %d, %+v, ok=%v", life, node, ok)
	}
	if life, node, _, ok := decodeEntry(frame([]byte{entryNegative, 7, 'x', 'y'})); !ok || life != 7 || node != nil {
		t.Errorf("negative entry with a later field: %d, %v, ok=%v", life, node, ok)
	}
	// Bytes after the frame are no field of anything.
	if _, _, ok := decodeNode(value + "x"); ok {
		t.Error("a value longer than its frame was read")
	}
	for what, v := range map[string]string{
		"version 0": "\x00" + value[1:], "version 2": "\x02" + value[1:], "version 255": "\xff" + value[1:],
	} {
		if _, _, ok := decodeNode(v); ok {
			t.Errorf("%s was read as a node", what)
		}
		if _, _, _, ok := decodeEntry(v); ok {
			t.Errorf("%s was read as an entry", what)
		}
	}
	fields[0] = wireTypeSymlink + 1
	if _, _, ok := decodeNode(frame(fields)); ok {
		t.Error("a node of a type this version does not know was read")
	}
	// A nanosecond count that is no nanosecond count.
	bad := append([]byte{wireTypeFile, flagModTime, 1, 1, 1, 0, 0, 0}, 2)
	bad = appendString(appendString(appendString(binary.AppendUvarint(bad, 1_000_000_000), "x"), ""), "")
	if _, _, ok := decodeNode(frame(bad)); ok {
		t.Error("a time of 1e9 nanoseconds was read")
	}
}

// The presence of a mode, flagModeSet, came after the first values: one
// without the flag holds a mode when it is nonzero (an older writer), none
// when it is 0. An explicit 0 is flagged, and described as "0000".
func TestWire_ModeSet(t *testing.T) {
	n := wireNodes()["file"]
	n.Sealed = nil
	for name, c := range map[string]struct {
		mode    fs.FileMode
		flagged bool
		has     bool
		desc    string
	}{
		"explicit 0":           {0, true, true, "0000"},
		"0 without the flag":   {0, false, false, ""},
		"older writer, 0644":   {0o644, false, true, "0644"},
		"flagged 0640":         {0o640, true, true, "0640"},
		"setuid alone flagged": {fs.ModeSetuid, true, true, "0" + strconv.FormatUint(uint64(fs.ModeSetuid), 8)},
	} {
		n.Mode, n.ModeSet = c.mode, false
		value, _ := clearWire.encodeNode(&n)
		fields := []byte(fieldsOf(t, value))
		if fields[1]&flagModeSet != 0 {
			t.Fatalf("%s: flagged without ModeSet", name)
		}
		if c.flagged {
			fields[1] |= flagModeSet
		}
		got, _, ok := decodeNode(frame(fields))
		if !ok || got.Mode != c.mode || got.HasMode() != c.has || got.ModeSet != c.flagged {
			t.Errorf("%s: read as ok=%v mode=%v set=%v has=%v", name, ok, got.Mode, got.ModeSet, got.HasMode())
		}
		d, err := Describe(KindListing, nodePrefix+"h", []byte(frame(fields)))
		if nd, isNode := d.(*NodeDescription); err != nil || !isNode || nd.Mode != c.desc {
			t.Errorf("%s: described as %+v (%v), want mode %q", name, d, err, c.desc)
		}
	}
}

// uvarint reads what binary.Uvarint reads and refuses what it refuses.
func TestReader_Uvarint(t *testing.T) {
	for _, in := range []string{
		"", "\x00", "\x7f", "\x80", "\x80\x01", "\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01",
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\x02", "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01",
		"\x80\x80\x80\x80\x80\x80\x80\x80\x80", "\x80\x00rest",
	} {
		want, n := binary.Uvarint([]byte(in))
		r := reader{s: in}
		got := r.uvarint()
		if r.bad != (n <= 0) || (n > 0 && (got != want || r.s != in[n:])) {
			t.Errorf("%q: read %d (bad=%v, %d left), binary.Uvarint reads %d (%d)", in, got, r.bad, len(r.s), want, n)
		}
	}
}

// Describe tells a value without opening it, and why one is not read.
func TestDescribe(t *testing.T) {
	n := wireNodes()["file"]
	clear, _ := clearWire.encodeNode(&n)
	sealed, _ := sealedWire.encodeNode(&n)
	field := nodePrefix + "h"

	got, err := Describe(KindListing, field, []byte(clear))
	must(t, err)
	raw, err := json.Marshal(got)
	must(t, err)
	want := `{"sealed":false,"id":"0b1f0c5e-1a2b-4c3d-8e9f-0123456789ab",` +
		`"parent_id":"ffffffff-ffff-4fff-bfff-ffffffffffff","type":"file","name":"report.pdf",` +
		`"mime":"application/pdf","version_id":"00000000-0000-0000-0000-000000000000",` +
		`"chunks":3,"size":20971520,"mode":"0644","mtime":"2026-10-13T08:30:12.123456789Z",` +
		`"ctime":"2026-10-01T00:00:00.123456Z","bytes":` + itoa(len(clear)-2) + `}`
	if string(raw) != want {
		t.Errorf("clear node described as\n%s\nwant\n%s", raw, want)
	}

	got, err = Describe(KindListing, field, []byte(sealed))
	must(t, err)
	d, ok := got.(*NodeDescription)
	if !ok || !d.Sealed || d.Name != "<AGE payload, 28 bytes>" || d.Target != "" || d.MIMEType != "" ||
		d.MIMETypeID != n.Sealed.MIMETypeID || d.Size != n.Size {
		t.Errorf("sealed node described as %+v", got)
	}
	raw, _ = json.Marshal(got)
	if strings.Contains(string(raw), "report") || strings.Contains(string(raw), "age-encryption") {
		t.Errorf("the description of a sealed node holds a name or a payload: %s", raw)
	}

	negative, _ := clearWire.encodeEntry(30*time.Second, nil)
	got, err = Describe(KindEntries, "h", []byte(negative))
	if e, ok := got.(*EntryDescription); err != nil || !ok || !e.Negative || e.LifeMS != 30000 || e.Node != nil {
		t.Errorf("negative entry described as %+v, %v", got, err)
	}
	positive, _ := sealedWire.encodeEntry(time.Minute, &n)
	got, err = Describe(KindEntries, "h", append([]byte(positive[:1]), reframed(t, positive, "later")...))
	if e, ok := got.(*EntryDescription); err != nil || !ok || e.Negative || e.LifeMS != 60000 || e.Node == nil ||
		!e.Node.Sealed || e.Node.ID != n.ID || e.Node.Unread != 0 {
		t.Errorf("positive entry described as %+v, %v", got, err)
	}
	later := frame(append([]byte(fieldsOf(t, clear)), "later"...))
	if got, err := Describe(KindListing, field, []byte(later)); err != nil || got.(*NodeDescription).Unread != 5 {
		t.Errorf("node with a later field described as %+v, %v", got, err)
	}

	if got, err := Describe(KindListing, metaField, []byte("1:60000")); err != nil ||
		*got.(*MetaDescription) != (MetaDescription{FormatVersion: 1, LifeMS: 60000}) {
		t.Errorf("meta described as %+v, %v", got, err)
	}
	if got, err := Describe(KindListing, etagField, []byte(`W/"7"`)); err != nil || got != `W/"7"` {
		t.Errorf("etag described as %v, %v", got, err)
	}
	if got, err := Describe(KindGeneration, "", []byte("42")); err != nil || got != uint64(42) {
		t.Errorf("generation described as %v, %v", got, err)
	}

	for what, c := range map[string]struct {
		kind, field, value, says string
	}{
		"former JSON":        {KindListing, field, `{"v":1,"name":"secret-name"}`, "first byte is 0x7b"},
		"another version":    {KindListing, field, "\x02" + clear[1:], "first byte is 0x02"},
		"cut node":           {KindListing, field, clear[:len(clear)-1], "does not parse"},
		"empty node":         {KindListing, field, "", "an empty node"},
		"node as an entry":   {KindEntries, "h", clear, "entry of"},
		"cut entry":          {KindEntries, "h", positive[:40], "does not parse"},
		"meta of a later":    {KindListing, metaField, "2:60000", "listing meta"},
		"generation of text": {KindGeneration, "", "secret-name", "generation of 11 bytes"},
	} {
		got, err := Describe(c.kind, c.field, []byte(c.value))
		if got != nil || !errors.Is(err, ErrUnreadable) || !strings.Contains(err.Error(), c.says) ||
			strings.Contains(err.Error(), "secret-name") {
			t.Errorf("%s: Describe = %v, %v", what, got, err)
		}
	}
	far := wireNodes()["dates no calendar text holds"]
	value, _ := clearWire.encodeNode(&far)
	got, err = Describe(KindListing, field, []byte(value))
	if d, ok := got.(*NodeDescription); err != nil || !ok || d.ModTime != "unix 1099511627776.000000005" {
		t.Errorf("node dated beyond the year 9999 described as %+v, %v", got, err)
	}
	if _, err := json.Marshal(got); err != nil {
		t.Errorf("its description is not JSON: %v", err)
	}
	if _, err := Describe("sub", "", nil); err == nil || errors.Is(err, ErrUnreadable) {
		t.Errorf("a kind of key the store has no more described: %v", err)
	}
	for _, kind := range []string{KindListingToken, KindEntryToken} {
		if got, err := Describe(kind, "", []byte("0123abcd")); err != nil || got != "0123abcd" {
			t.Errorf("token of kind %s described as %v, %v", kind, got, err)
		}
	}
	for _, kind := range []string{KindListing, KindEntries} {
		got, err := Describe(kind, tokensField, []byte("t1,t2"))
		if d, ok := got.(*TokensDescription); err != nil || !ok || len(d.Tokens) != 2 || d.Tokens[1] != "t2" {
			t.Errorf("tokens of kind %s described as %+v, %v", kind, got, err)
		}
	}
	if _, err := Describe(KindListing, "secret-name", nil); err == nil || strings.Contains(err.Error(), "secret-name") {
		t.Errorf("an unknown field of a listing: %v", err)
	}
}

// reframed is the frame of value with tail added to its fields, without the
// version byte.
func reframed(t *testing.T, value, tail string) string {
	t.Helper()

	return frame([]byte(fieldsOf(t, value) + tail))[1:]
}

func itoa(n int) string {
	raw, _ := json.Marshal(n)

	return string(raw)
}

func TestParseKey(t *testing.T) {
	s := &Store{prefix: "a:b"}
	key := s.key("dr-1", KindEntries, "abc")
	if got, ok := ParseKey(key); !ok || got != (Key{Prefix: "a:b", DataroomID: "dr-1", Kind: KindEntries, Hash: "abc"}) {
		t.Errorf("ParseKey(%q) = %+v, %v", key, got, ok)
	}
	for _, bad := range []string{
		"", "a:b", "a:v1:{d}:ls:h", "a:v2:{d}:zz:h", "a:v2:{d}:sub:h", "a:v2:{d}:ls:", "a:v2:{}:ls:h", ":v2:{d}:ls:h",
		"a:v2:{d:ls:h",
	} {
		if got, ok := ParseKey(bad); ok {
			t.Errorf("ParseKey(%q) = %+v", bad, got)
		}
	}
	if p := KeyPattern("", "", ""); p != "retyc:v2:{*}:*:*" {
		t.Errorf("KeyPattern of everything = %q", p)
	}
	if p := KeyPattern("t*[x]", "d?", KindListing); p != `t\*\[x\]:v2:{d\?}:ls:*` {
		t.Errorf("KeyPattern escaped = %q", p)
	}
}

// FuzzDecodeNode: no value makes a decoder panic, and a value that is read
// is written back as a value that reads the same.
func FuzzDecodeNode(f *testing.F) {
	for _, n := range wireNodes() {
		for _, s := range []*Store{clearWire, sealedWire} {
			value, _ := s.encodeNode(&n)
			entry, _ := s.encodeEntry(time.Minute, &n)
			for _, v := range []string{value, entry} {
				f.Add([]byte(v))
				f.Add([]byte(v[:len(v)/2]))
				f.Add([]byte(v + "tail"))
				f.Add(append([]byte(v[:2]), strings.Repeat("\xff", 11)...))
				flipped := []byte(v)
				flipped[len(flipped)/3] ^= 0x55
				f.Add(flipped)
				f.Add([]byte(frame(append([]byte(v[2:]), 1, 2, 3))))
			}
		}
	}
	negative, _ := clearWire.encodeEntry(time.Second, nil)
	f.Add([]byte(negative))
	f.Add([]byte{})
	f.Add([]byte{wireVersion})
	f.Add([]byte(`{"v":1,"id":"i","name":"x"}`))

	// armoredLike tells a sealed node unarmor would not keep as it is: a
	// payload the store never returns, since it stores none with an armor.
	armoredLike := func(n *metastore.Node) bool {
		for _, p := range []string{n.Sealed.Name, n.Sealed.Target, n.Sealed.MIMEType} {
			if strings.HasPrefix(strings.TrimSpace(p), armor.Header) {
				return true
			}
		}

		return false
	}
	again := func(t *testing.T, n metastore.Node, sealed bool) (metastore.Node, bool) {
		s := clearWire
		if sealed {
			s = sealedWire
		}
		value, ok := s.encodeNode(&n)
		if !ok {
			t.Fatalf("a node that was read is not written: %+v", n)
		}
		got, gotSealed, ok := decodeNode(value)
		if !ok || gotSealed != sealed {
			t.Fatalf("a node written is not read back: ok=%v sealed=%v", ok, gotSealed)
		}

		return got, true
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, kind := range []string{KindListing, KindEntries, KindGeneration, KindListingToken, KindEntryToken} {
			for _, field := range []string{nodePrefix + "h", metaField, etagField, tokensField} {
				if d, err := Describe(kind, field, data); err == nil {
					if _, err := json.Marshal(d); err != nil {
						t.Fatalf("a description that is not JSON: %v", err)
					}
				}
			}
		}
		if n, sealed, ok := decodeNode(string(data)); ok {
			if n.Name == "" && n.Sealed.Name == "" {
				t.Fatal("a node without a name was read")
			}
			if !sealed || !armoredLike(&n) {
				if got, _ := again(t, n, sealed); !reflect.DeepEqual(got, n) {
					t.Fatalf("read\n%+v\nthen written and read as\n%+v", n, got)
				}
			}
		}
		if life, n, sealed, ok := decodeEntry(string(data)); ok {
			if life <= 0 {
				t.Fatalf("an entry with the lifetime %d was read", life)
			}
			if n != nil && (!sealed || !armoredLike(n)) {
				if got, _ := again(t, *n, sealed); !reflect.DeepEqual(got, *n) {
					t.Fatalf("entry: read\n%+v\nthen written and read as\n%+v", *n, got)
				}
			}
		}
	})
}

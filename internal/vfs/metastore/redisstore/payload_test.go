package redisstore

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"

	"github.com/retyc/retyc-cli/internal/crypto"
	"github.com/retyc/retyc-cli/internal/vfs/metastore"
)

// ageCodec is a codec over real AGE payloads: it opens a sealed node as
// vfs.FS does, armored or binary.
type ageCodec struct {
	fakeCodec
	identity *age.HybridIdentity
}

func (c *ageCodec) Open(_ context.Context, _ string, n *metastore.Node) error {
	name, err := crypto.DecryptPayloadToString(n.Sealed.Name, c.identity)
	if err != nil {
		return err
	}
	if name == "" {
		return errors.New("empty name")
	}
	n.Name, n.Target, n.MIMEType = name, "", ""
	if n.Sealed.Target != "" {
		if n.Target, err = crypto.DecryptPayloadToString(n.Sealed.Target, c.identity); err != nil {
			return err
		}
	}
	if n.Sealed.MIMEType != "" {
		n.MIMEType, _ = crypto.DecryptPayloadToString(n.Sealed.MIMEType, c.identity)
	}

	return nil
}

// ageEnv is an env whose stores are bound to an ageCodec; armored encrypts a
// string the way the API's clients do.
func ageEnv(t *testing.T) (e *env, bind func(*Store) *Store, armored func(string) string) {
	t.Helper()
	e = newEnv(t)
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	codec := &ageCodec{identity: identity}
	pub := identity.Recipient().String()

	return e, func(s *Store) *Store {
			s.Bind(codec)

			return s
		}, func(v string) string {
			t.Helper()
			enc, err := crypto.EncryptStringForKeys(v, []string{pub})
			if err != nil {
				t.Fatal(err)
			}

			return enc
		}
}

// dearmor is the binary AGE payload an armor encodes.
func dearmor(t *testing.T, armored string) string {
	t.Helper()
	raw, err := io.ReadAll(armor.NewReader(strings.NewReader(armored)))
	if err != nil || len(raw) == 0 {
		t.Fatalf("dearmoring a test payload: %v", err)
	}

	return string(raw)
}

// assertNoArmor fails when value holds anything of the armored form of one of
// the payloads, or one of the plaintexts.
func assertNoArmor(t *testing.T, what, value string, armoredPayloads, plaintexts []string) {
	t.Helper()
	if strings.Contains(value, "BEGIN AGE") || strings.Contains(value, "END AGE") {
		t.Errorf("%s holds an armor", what)
	}
	for _, p := range armoredPayloads {
		lines := strings.Split(strings.TrimSpace(p), "\n")
		if len(lines) < 4 {
			t.Fatalf("test payload of %d lines", len(lines))
		}
		// Every full base64 line of the armor's body.
		for _, line := range lines[1 : len(lines)-2] {
			if strings.Contains(value, strings.TrimSpace(line)) {
				t.Fatalf("%s holds the base64 of a payload", what)
			}
		}
	}
	for _, p := range plaintexts {
		if strings.Contains(value, p) {
			t.Errorf("%s holds %q in clear", what, p)
		}
	}
}

// In high confidentiality a value holds, besides its other fields, the AGE payloads
// the API sent without their armor: the bytes are the API's, the store
// encrypts nothing, and reads hand the payloads back in binary.
func TestSealed_StoredBinary(t *testing.T) {
	e, bind, armored := ageEnv(t)
	high, clear := bind(e.store(true)), bind(e.store(false))
	ctx := context.Background()
	const dir = "/d"

	doc := metastore.Node{ID: "id-doc", Name: "secret-report.pdf", Type: metastore.TypeFile, Size: 7}
	doc.Sealed = metastore.Sealed{Name: armored(doc.Name), MIMEType: armored("application/x-secret-mime")}
	link := metastore.Node{ID: "id-link", Name: "secret-link", Type: metastore.TypeSymlink}
	link.Sealed = metastore.Sealed{
		Name: armored(link.Name), Target: armored("/secret-target"), MIMEType: armored("inode/x-secret-kind"),
		MIMETypeID: "0b1f0c5e-0000-4000-8000-000000000001",
	}
	armors := []string{
		doc.Sealed.Name, doc.Sealed.MIMEType, link.Sealed.Name, link.Sealed.Target, link.Sealed.MIMEType,
	}
	plain := []string{"secret-report", "x-secret-mime", "secret-link", "secret-target", "x-secret-kind"}
	if !strings.HasPrefix(doc.Sealed.Name, armor.Header) {
		t.Fatal("the test payloads are not armored")
	}

	put(t, high, dir, doc, link)
	must(t, high.PutEntry(ctx, ek(dir, link.Name), &metastore.Entry{Node: &link, FetchedAt: time.Now()}))
	f, _ := high.folder(dr, dir)
	rawOf := func(n metastore.Node) (node, entry string) {
		t.Helper()
		nh, _ := f.hash(n.Name)

		return e.raw.HGet(ctx, f.ls, nodePrefix+nh).Val(), e.raw.HGet(ctx, f.entries, nh).Val()
	}

	// The raw values.
	assertNoArmor(t, "Redis", e.dump(), armors, plain)
	for _, n := range []metastore.Node{doc, link} {
		value, entry := rawOf(n)
		want := []string{dearmor(t, n.Sealed.Name), dearmor(t, n.Sealed.MIMEType)}
		if n.Sealed.Target != "" {
			want = append(want, dearmor(t, n.Sealed.Target))
		}
		values := map[string]string{"node": value}
		if n.ID == link.ID {
			values["entry"] = entry
		}
		for what, v := range values {
			// Each payload is in the value once, in binary, and what is not
			// a payload is a few dozen bytes.
			rest := len(v)
			for _, p := range want {
				if strings.Count(v, p) != 1 {
					t.Fatalf("%s of %s: a dearmored payload is not in the value exactly once", what, n.ID)
				}
				rest -= len(p)
			}
			if strings.Count(v, "age-encryption.org") != len(want) || rest <= 0 || rest > 64 {
				t.Fatalf("%s of %s: %d payloads announced, %d bytes besides them", what, n.ID,
					strings.Count(v, "age-encryption.org"), rest)
			}
		}
		w, sealed, ok := decodeNode(value)
		if !ok || !sealed || w.Name != "" || w.Target != "" || w.MIMEType != "" ||
			w.Sealed.Name != dearmor(t, n.Sealed.Name) || w.Sealed.MIMETypeID != n.Sealed.MIMETypeID ||
			len(w.Sealed.Name)+len(w.Sealed.Target)+len(w.Sealed.MIMEType) != len(strings.Join(want, "")) {
			t.Fatalf("value of %s: ok=%v sealed=%v, decoded as %+v", n.ID, ok, sealed, w)
		}
	}

	// Both configurations read them: binary payloads, which open.
	for mode, s := range map[string]*Store{"high": high, "clear": clear} {
		nodes, ok := held(t, s, dir)
		if !ok || len(nodes) != 2 {
			t.Fatalf("%s: listing read back: %d nodes, ok=%v", mode, len(nodes), ok)
		}
		got, _, isHeld, err := s.GetNode(ctx, lk(dir), link.Name)
		if err != nil || !isHeld || got == nil {
			t.Fatalf("%s: GetNode = %v, %v, %v", mode, got, isHeld, err)
		}
		en, ok, err := s.GetEntry(ctx, ek(dir, link.Name))
		if err != nil || !ok || en.Node == nil {
			t.Fatalf("%s: GetEntry = %v, %v, %v", mode, en, ok, err)
		}
		var listed metastore.Node
		for _, n := range nodes {
			if n.ID == link.ID {
				listed = n
			}
		}
		for from, n := range map[string]metastore.Node{"listing": listed, "node": *got, "entry": *en.Node} {
			if n.Name != link.Name || n.Target != "/secret-target" || n.MIMEType != "inode/x-secret-kind" {
				t.Errorf("%s, %s: opened as (%q, %q, %q)", mode, from, n.Name, n.Target, n.MIMEType)
			}
			if n.Sealed.Name != dearmor(t, link.Sealed.Name) || n.Sealed.Target != dearmor(t, link.Sealed.Target) ||
				n.Sealed.MIMEType != dearmor(t, link.Sealed.MIMEType) || n.Sealed.MIMETypeID != link.Sealed.MIMETypeID {
				t.Errorf("%s, %s: the sealed fields are not the binary payloads", mode, from)
			}
		}
	}

	// A node read from Redis and written again is stored byte for byte.
	nodes, _ := held(t, high, dir)
	beforeDoc, _ := rawOf(doc)
	beforeLink, beforeEntry := rawOf(link)
	put(t, high, dir, nodes...)
	for _, n := range nodes {
		if n.ID == link.ID {
			_, err := high.UpsertNode(ctx, lk(dir), n)
			must(t, err)
			must(t, high.PutEntry(ctx, ek(dir, n.Name), &metastore.Entry{Node: &n, FetchedAt: time.Now()}))
		}
	}
	afterDoc, _ := rawOf(doc)
	afterLink, afterEntry := rawOf(link)
	if afterDoc != beforeDoc || afterLink != beforeLink || afterEntry != beforeEntry {
		t.Error("a binary payload written again changed the stored value")
	}

	// A clear store writes names and no payload; the high one reads them.
	put(t, clear, "/c", doc)
	fc, _ := clear.folder(dr, "/c")
	dh, _ := fc.hash(doc.Name)
	v := e.raw.HGet(ctx, fc.ls, nodePrefix+dh).Val()
	if n, sealed, ok := decodeNode(v); !ok || sealed || n.Name != doc.Name || n.Sealed != (metastore.Sealed{}) ||
		strings.Contains(v, "age-encryption.org") || len(v) > 64 {
		t.Errorf("a clear node holds more than its fields: %q", v)
	}
	if nodes, ok := held(t, high, "/c"); !ok || len(nodes) != 1 || nodes[0].Name != doc.Name {
		t.Errorf("a clear listing read by a high confidentiality store: %+v ok=%v", nodes, ok)
	}
}

// An armor that does not decode is no sealed form: nothing of the node is
// written, and the listing it belonged to goes.
func TestSealed_InvalidArmor(t *testing.T) {
	e, bind, armored := ageEnv(t)
	high := bind(e.store(true))
	ctx := context.Background()
	const dir = "/d"
	good := metastore.Node{ID: "id-good", Name: "good", Type: metastore.TypeFile}
	good.Sealed.Name = armored(good.Name)
	broken := armor.Header + "\nnot base64 !!!\n" + armor.Footer + "\n"
	cut := good.Sealed.Name[:len(good.Sealed.Name)/2]
	empty := armor.Header + "\n" + armor.Footer + "\n"

	for what, bad := range map[string]metastore.Sealed{
		"broken name":   {Name: broken},
		"cut name":      {Name: cut},
		"empty name":    {Name: empty},
		"broken target": {Name: armored("victim"), Target: broken},
	} {
		victim := metastore.Node{ID: "id-victim", Name: "victim", Type: metastore.TypeSymlink, Sealed: bad}

		put(t, high, dir, good)
		before := gen(t, high, dir)
		g, err := high.UpsertNode(ctx, lk(dir), victim)
		must(t, err)
		if _, ok := held(t, high, dir); ok || g <= before {
			t.Errorf("%s: upsert kept the listing (gen %d from %d)", what, g, before)
		}

		put(t, high, dir, good)
		put(t, high, dir, good, victim)
		if _, ok := held(t, high, dir); ok {
			t.Errorf("%s: a listing holding the node was stored, or the previous one kept", what)
		}

		must(t, high.PutEntry(ctx, ek(dir, "victim"), &metastore.Entry{Node: &good, FetchedAt: time.Now()}))
		must(t, high.PutEntry(ctx, ek(dir, "victim"), &metastore.Entry{Node: &victim, FetchedAt: time.Now()}))
		if _, ok, err := high.GetEntry(ctx, ek(dir, "victim")); ok || err != nil {
			t.Errorf("%s: the entry was stored, or the previous one kept (err=%v)", what, err)
		}
		if dump := e.dump(); strings.Contains(dump, "victim") || strings.Contains(dump, "not base64") {
			t.Errorf("%s: something of the node reached Redis", what)
		}
	}

	// The MIME type is cosmetic: a type_enc that does not decode is left out.
	odd := good
	odd.Sealed.MIMEType = broken
	put(t, high, dir, odd)
	nodes, ok := held(t, high, dir)
	if !ok || len(nodes) != 1 || nodes[0].Name != "good" || nodes[0].Sealed.MIMEType != "" {
		t.Errorf("node with a broken type_enc: %+v ok=%v", nodes, ok)
	}
	if strings.Contains(e.dump(), "not base64") {
		t.Error("a broken type_enc reached Redis")
	}
}

// rawSealed is the value of a sealed symlink written by hand, each payload
// announced with the length given: what a test builds a value the store
// never writes from.
func rawSealed(id string, lens [3]uint64, payloads [3]string) string {
	b := appendIdent([]byte{wireTypeSymlink, flagSealed}, id)
	b = append(b, 1, 1) // no parent, no version
	b = append(b, 0, 0, 0)
	b = append(b, 1) // no MIME type ID
	for i, p := range payloads {
		b = append(binary.AppendUvarint(b, lens[i]), p...)
	}

	return frame(b)
}

// fieldsOf is the fields of a value, without its frame.
func fieldsOf(t *testing.T, value string) string {
	t.Helper()
	r, ok := unframe(value)
	if !ok {
		t.Fatal("not a frame")
	}

	return r.s
}

// A value that is not exactly a frame of this version, or whose fields do
// not parse or do not open, is absent: never an error, never a panic.
func TestSealed_InconsistentValues_Absent(t *testing.T) {
	e, bind, armored := ageEnv(t)
	s := bind(e.store(true))
	ctx := context.Background()
	const dir = "/d"
	x := metastore.Node{ID: "id-x", Name: "x", Type: metastore.TypeSymlink}
	x.Sealed = metastore.Sealed{Name: armored("x"), Target: armored("/t"), MIMEType: armored("text/plain")}
	y := metastore.Node{ID: "id-y", Name: "y", Type: metastore.TypeFile}
	y.Sealed.Name = armored("y")
	f, _ := s.folder(dr, dir)
	xh, _ := f.hash("x")

	put(t, s, dir, x, y)
	valid := e.raw.HGet(ctx, f.ls, nodePrefix+xh).Val()
	payloads := [3]string{dearmor(t, x.Sealed.Name), dearmor(t, x.Sealed.Target), dearmor(t, x.Sealed.MIMEType)}
	nameLen, targetLen, mimeLen := uint64(len(payloads[0])), uint64(len(payloads[1])), uint64(len(payloads[2]))
	withLens := func(name, target, mime uint64) string {
		return rawSealed(x.ID, [3]uint64{name, target, mime}, payloads)
	}
	// The layout the cases below are built on is the one the store writes.
	if withLens(nameLen, targetLen, mimeLen) != valid {
		t.Fatal("rawSealed does not build the value the store writes")
	}
	fields := fieldsOf(t, valid)
	unknownType := []byte(fields)
	unknownType[0] = 9
	zeros := strings.Repeat("\x00", len(payloads[0]))

	nodeValues := map[string]string{
		"empty":                       "",
		"the version alone":           valid[:1],
		"cut by one byte":             valid[:len(valid)-1],
		"one byte too long":           valid + "!",
		"fields cut by one byte":      frame([]byte(fields[:len(fields)-1])),
		"fields cut in a payload":     frame([]byte(fields[:len(fields)/2])),
		"no version":                  valid[1:],
		"another version":             "\x02" + valid[1:],
		"frame length that overflows": "\x01" + strings.Repeat("\xff", 11) + fields,
		"frame length beyond":         "\x01" + string(binary.AppendUvarint(nil, uint64(len(fields))+1)) + fields,
		"unknown type":                frame(unknownType),
		"name length zero":            withLens(0, targetLen, mimeLen),
		"lengths too long":            withLens(nameLen, targetLen, mimeLen+1),
		"lengths that overflow":       withLens(math.MaxUint64, math.MaxUint64, 2),
		"length beyond the value":     withLens(math.MaxInt64, 0, 0),
		"varint that does not end":    frame(append([]byte(fields[:2]), strings.Repeat("\xff", 12)...)),
		"the former JSON":             `{"v":1,"id":"id-x","name":"x"}`,
		"payloads that do not open":   rawSealed(x.ID, [3]uint64{nameLen, 0, 0}, [3]string{zeros, "", ""}),
	}
	for what, value := range nodeValues {
		put(t, s, dir, x, y)
		must(t, e.raw.HSet(ctx, f.ls, nodePrefix+xh, value).Err())
		if l, ok, err := s.GetListing(ctx, lk(dir)); l != nil || ok || err != nil {
			t.Errorf("%s: GetListing = %v, %v, %v", what, l, ok, err)
		}
		if n, _, isHeld, err := s.GetNode(ctx, lk(dir), "x"); n != nil || isHeld || err != nil {
			t.Errorf("%s: GetNode = %v, %v, %v", what, n, isHeld, err)
		}
		if n, _, isHeld, err := s.GetNode(ctx, lk(dir), "y"); n == nil || !isHeld || err != nil {
			t.Errorf("%s: GetNode of a readable sibling = %v, %v, %v", what, n, isHeld, err)
		}
	}

	// The same for the node of an entry.
	must(t, s.PutEntry(ctx, ek(dir, "x"), &metastore.Entry{Node: &x, FetchedAt: time.Now()}))
	validEntry := e.raw.HGet(ctx, f.entries, xh).Val()
	if en, ok, err := s.GetEntry(ctx, ek(dir, "x")); en == nil || !ok || err != nil {
		t.Fatalf("GetEntry of the valid entry = %v, %v, %v", en, ok, err)
	}
	if !strings.HasSuffix(validEntry, fields) {
		t.Fatal("the entry does not end with the fields of its node")
	}
	unopenable := fieldsOf(t, rawSealed(x.ID, [3]uint64{nameLen, 0, 0}, [3]string{zeros, "", ""}))
	entryOf := func(kind byte, life, nodeLen uint64, node string) string {
		b := binary.AppendUvarint(binary.AppendUvarint([]byte{kind}, life), nodeLen)

		return frame(append(b, node...))
	}
	if entryOf(entryPositive, 30000, uint64(len(fields)), fields) != validEntry {
		t.Fatal("entryOf does not build the value the store writes")
	}
	for what, value := range map[string]string{
		"empty":                   "",
		"cut by one byte":         validEntry[:len(validEntry)-1],
		"one byte too long":       validEntry + "!",
		"another version":         "\x02" + validEntry[1:],
		"no lifetime":             entryOf(entryPositive, 0, uint64(len(fields)), fields),
		"lifetime that overflows": entryOf(entryPositive, math.MaxUint64, uint64(len(fields)), fields),
		"unknown kind":            entryOf(7, 30000, uint64(len(fields)), fields),
		"node length beyond":      entryOf(entryPositive, 30000, uint64(len(fields))+1, fields),
		"node length overflows":   entryOf(entryPositive, 30000, math.MaxUint64, fields),
		"node cut by one byte":    entryOf(entryPositive, 30000, uint64(len(fields))-1, fields[:len(fields)-1]),
		"positive without node":   frame(binary.AppendUvarint([]byte{entryPositive}, 30000)),
		"negative, no lifetime":   frame([]byte{entryNegative, 0}),
		"the former JSON":         `{"v":1,"life_ms":30000}`,
		"node that does not open": entryOf(entryPositive, 30000, uint64(len(unopenable)), unopenable),
	} {
		must(t, e.raw.HSet(ctx, f.entries, xh, value).Err())
		must(t, e.raw.HPExpire(ctx, f.entries, time.Minute, xh).Err())
		if en, ok, err := s.GetEntry(ctx, ek(dir, "x")); en != nil || ok || err != nil {
			t.Errorf("entry, %s: GetEntry = %v, %v, %v", what, en, ok, err)
		}
	}
}

// The lengths of a value come from Redis: none of them may slice out of
// range or overflow, whatever they are. What a block holds after its last
// field is not an error (see wire.go: a later version adds fields there).
func TestDecodeNode_Lengths(t *testing.T) {
	payloads := [3]string{"nnnn", "tt", "mmm"}
	for _, c := range []struct {
		name, target, mime uint64
		ok                 bool
		want               metastore.Sealed
	}{
		{4, 2, 3, true, metastore.Sealed{Name: "nnnn", Target: "tt", MIMEType: "mmm"}},
		{4, 2, 2, true, metastore.Sealed{Name: "nnnn", Target: "tt", MIMEType: "mm"}}, // one byte unread
		{4, 2, 0, true, metastore.Sealed{Name: "nnnn", Target: "tt"}},
		{0, 2, 3, false, metastore.Sealed{}},
		{4, 2, 4, false, metastore.Sealed{}},
		{4, 9, 3, false, metastore.Sealed{}},
		{12, 0, 0, false, metastore.Sealed{}},
		{math.MaxUint64, math.MaxUint64, 11, false, metastore.Sealed{}},
		{math.MaxInt64, math.MaxInt64, 2, false, metastore.Sealed{}},
		{4, math.MaxUint64 - 3, 3, false, metastore.Sealed{}},
		{1 << 63, 2, 3, false, metastore.Sealed{}},
	} {
		n, sealed, ok := decodeNode(rawSealed("i", [3]uint64{c.name, c.target, c.mime}, payloads))
		if ok != c.ok || sealed != c.ok || n.Sealed != c.want {
			t.Errorf("lengths (%d, %d, %d): ok=%v sealed=%v %+v, want %v %+v",
				c.name, c.target, c.mime, ok, sealed, n.Sealed, c.ok, c.want)
		}
	}
}

// A payload that is not armored is binary already; an armor is decoded, and
// one that does not decode is refused.
func TestUnarmor(t *testing.T) {
	_, _, armored := ageEnv(t)
	enc := armored("name")
	bin, ok := unarmor(enc)
	if !ok || bin != dearmor(t, enc) || !strings.HasPrefix(bin, "age-encryption.org/v1\n") {
		t.Fatalf("unarmor of an armored payload: ok=%v, %d bytes", ok, len(bin))
	}
	if again, ok := unarmor(bin); !ok || again != bin {
		t.Error("a binary payload was not kept as it is")
	}
	if spaced, ok := unarmor("\n\n" + enc + "\n"); !ok || spaced != bin {
		t.Error("an armor between blank lines was not decoded")
	}
	if v, ok := unarmor(""); !ok || v != "" {
		t.Error("no payload is not an error")
	}
	for _, bad := range []string{
		armor.Header, armor.Header + "\n" + armor.Footer, enc[:len(enc)-10], enc + "trailing",
		"  " + enc, // what the armor reader refuses is refused, not taken for binary
		strings.Replace(enc, "\n", "\n*", 1),
	} {
		if v, ok := unarmor(bad); ok || v != "" {
			t.Errorf("a broken armor was decoded to %d bytes", len(v))
		}
	}
}

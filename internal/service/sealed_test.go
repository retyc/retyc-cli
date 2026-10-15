package service

import (
	"context"
	"io"
	"strings"
	"testing"

	"filippo.io/age/armor"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/crypto"
)

// Peek answers what the cache holds and starts nothing.
func TestSessionCache_Peek(t *testing.T) {
	var c SessionCache
	if sess, ok := c.Peek("dr1"); ok || sess != nil {
		t.Fatalf("Peek of an empty cache = (%v, %v)", sess, ok)
	}
	want := &DataroomSession{NameSalt: "s"}
	c.Store("dr1", want)
	if sess, ok := c.Peek("dr1"); !ok || sess != want {
		t.Errorf("Peek = (%v, %v), want the session stored", sess, ok)
	}
	if _, ok := c.Peek("dr2"); ok {
		t.Error("Peek found a session for another dataroom")
	}
}

// A node decrypted from an answer of the API keeps what the API sent, and
// OpenSealed gives back from it what the listing decrypted.
func TestSealedNodeRoundTrip(t *testing.T) {
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pub := identity.Recipient().String()
	seal := func(v string) string {
		enc, err := crypto.EncryptStringForKeys(v, []string{pub})
		if err != nil {
			t.Fatal(err)
		}

		return enc
	}
	sess := (&DataroomSession{Identity: identity, PublicKey: pub, NameSalt: "salt"}).AssumeLegacyAPI()
	if got := sess.NameHash("f.txt"); got != nodeNameHash("f.txt", "salt") {
		t.Errorf("NameHash = %q, want the name hash of a node", got)
	}

	typeEnc, targetEnc := seal("text/plain"), seal("../t")
	file := api.DataroomNodeItem{Node: api.DataroomNode{
		ID: "n1", Type: api.NodeTypeFile, NameEnc: seal("f.txt"), TypeEnc: &typeEnc,
	}}
	link := api.DataroomNodeItem{Node: api.DataroomNode{
		ID: "n2", Type: api.NodeTypeSymlink, NameEnc: seal("l"), TargetEnc: &targetEnc,
	}}
	ctx := context.Background()
	for _, item := range []api.DataroomNodeItem{file, link} {
		info := nodeFromItem(ctx, nil, "dr1", &item, sess)
		sealed := info.Sealed()
		if sealed.NameEnc != item.Node.NameEnc {
			t.Fatalf("%s: Sealed().NameEnc is not the name_enc of the API", info.Name)
		}
		name, target, mimeType, err := sess.OpenSealed(sealed)
		if err != nil || name != info.Name || target != info.Target() || mimeType != info.MIMEType {
			t.Errorf("OpenSealed = (%q, %q, %q, %v), want (%q, %q, %q)",
				name, target, mimeType, err, info.Name, info.Target(), info.MIMEType)
		}
	}
	if _, _, _, err := sess.OpenSealed(SealedNode{}); err == nil {
		t.Error("OpenSealed of a node without name_enc succeeded")
	}
	if _, _, _, err := sess.OpenSealed(SealedNode{NameEnc: "not armored"}); err == nil {
		t.Error("OpenSealed of a name that does not decrypt succeeded")
	}
}

// OpenSealed runs under a lock every operation of a mount waits for: a row of
// the MIME table is read from the table the session holds, never loaded for
// it. The type is "" until a listing loaded the table.
func TestOpenSealed_NeverLoadsTheMimeTable(t *testing.T) {
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	fake := newMimeAPI(t, identity)
	pdf := fake.addType("application/pdf")
	client := newExportTestClient(fake.server())
	sess := fake.session()
	nameEnc, err := crypto.EncryptStringForKeys("f.pdf", []string{identity.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	sealed := SealedNode{NameEnc: nameEnc, MIMETypeID: pdf}

	name, _, mimeType, err := sess.OpenSealed(sealed)
	if err != nil || name != "f.pdf" || mimeType != "" {
		t.Errorf("OpenSealed before the table is loaded = (%q, %q, %v), want the name and no type", name, mimeType, err)
	}
	if _, _, mimeType, _ = sess.OpenSealed(SealedNode{NameEnc: nameEnc, MIMETypeID: "mt-unknown"}); mimeType != "" {
		t.Errorf("OpenSealed of an unknown row = %q", mimeType)
	}
	if got := fake.count("GET /dataroom/dr1/mime-types"); got != 0 {
		t.Fatalf("OpenSealed fetched the MIME table %d times, want none", got)
	}

	// What a listing does, outside the lock.
	if got := sess.mimeTypeByID(context.Background(), client, "dr1", pdf); got != "application/pdf" {
		t.Fatalf("mimeTypeByID = %q", got)
	}
	if _, _, mimeType, _ = sess.OpenSealed(sealed); mimeType != "application/pdf" {
		t.Errorf("OpenSealed once the table is loaded = %q, want application/pdf", mimeType)
	}
	// A row added since is not reloaded for either.
	if _, _, mimeType, _ = sess.OpenSealed(SealedNode{NameEnc: nameEnc, MIMETypeID: "mt-unknown"}); mimeType != "" {
		t.Errorf("OpenSealed of an unknown row = %q", mimeType)
	}
	if got := fake.count("GET /dataroom/dr1/mime-types"); got != 1 {
		t.Errorf("MIME table fetched %d times, want the one load of the listing", got)
	}
}

// A sealed field is opened whether it comes armored, as the API sends it, or
// binary, the same payload without its armor, as a store hands it back.
func TestOpenSealed_ArmoredOrBinary(t *testing.T) {
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pub := identity.Recipient().String()
	seal := func(v string) (armored, binary string) {
		t.Helper()
		armored, err := crypto.EncryptStringForKeys(v, []string{pub})
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(armor.NewReader(strings.NewReader(armored)))
		if err != nil || len(raw) == 0 {
			t.Fatalf("dearmoring: %v", err)
		}

		return armored, string(raw)
	}
	sess := (&DataroomSession{Identity: identity, PublicKey: pub}).AssumeLegacyAPI()

	nameArmored, nameBinary := seal("report.pdf")
	targetArmored, targetBinary := seal("../t")
	typeArmored, typeBinary := seal("application/pdf")
	if strings.Contains(nameBinary, "BEGIN AGE") || len(nameBinary) >= len(nameArmored) {
		t.Fatal("the binary payload is not the armored one without its armor")
	}
	for form, sealed := range map[string]SealedNode{
		"armored": {NameEnc: nameArmored, TargetEnc: targetArmored, TypeEnc: typeArmored},
		"binary":  {NameEnc: nameBinary, TargetEnc: targetBinary, TypeEnc: typeBinary},
		"mixed":   {NameEnc: nameBinary, TargetEnc: targetArmored, TypeEnc: typeBinary},
	} {
		name, target, mimeType, err := sess.OpenSealed(sealed)
		if err != nil || name != "report.pdf" || target != "../t" || mimeType != "application/pdf" {
			t.Errorf("%s: OpenSealed = (%q, %q, %q, %v)", form, name, target, mimeType, err)
		}
	}
	if a, errA := sess.OpenSealedName(nameArmored); errA != nil {
		t.Fatal(errA)
	} else if b, errB := sess.OpenSealedName(nameBinary); errB != nil || a != b {
		t.Errorf("OpenSealedName: %q armored, %q binary (%v)", a, b, errB)
	}

	// A binary payload that is damaged fails, and a damaged type_enc is no type.
	flipped := []byte(nameBinary)
	flipped[len(flipped)-1] ^= 0xff
	for what, bad := range map[string]string{
		"cut": nameBinary[:len(nameBinary)-20], "last byte": string(flipped),
		"header only": "age-encryption.org/v1\n", "zeroes": strings.Repeat("\x00", 64),
	} {
		if name, err := sess.OpenSealedName(bad); err == nil {
			t.Errorf("%s: OpenSealedName = %q", what, name)
		}
		if target, err := sess.OpenSealedTarget(bad); err == nil {
			t.Errorf("%s: OpenSealedTarget = %q", what, target)
		}
		if mimeType := sess.SealedMIMEType("", bad); mimeType != "" {
			t.Errorf("%s: SealedMIMEType = %q", what, mimeType)
		}
	}
}

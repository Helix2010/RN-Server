package apktest

import (
	"bytes"
	"testing"

	"github.com/Helix2010/RN-Server/signing/trustroots"
)

func TestDefaultRootsAreNormalized(t *testing.T) {
	r := DefaultRoots()
	n, err := r.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	if !trustroots.Equal(r, n) {
		t.Fatalf("DefaultRoots is not in normalized form: %+v vs %+v", r, n)
	}
}

func TestStripSigningBlockRoundTrip(t *testing.T) {
	manifest := []byte{0x03, 0x00, 0x08, 0x00, 0x08, 0x00, 0x00, 0x00}
	files := []File{{Name: "AndroidManifest.xml", Data: manifest, Deflate: true}, {Name: "resources.arsc", Data: []byte("abcd")}}
	plain, err := WriteZip(files, ZipOptions{Align: true})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := WriteZip(files, ZipOptions{Align: true, SigningBlock: true})
	if err != nil {
		t.Fatal(err)
	}
	stripped, err := StripSigningBlock(signed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stripped, plain) {
		t.Fatal("stripping the signing block does not give back the unsigned archive")
	}
}

package cmd

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/csv"
	"slices"
	"testing"
	"time"
)

func TestDecodePemsByType(t *testing.T) {
	a := newCert(t, certOpts{cn: "a", isCA: true})
	b := newCert(t, certOpts{cn: "b", parent: a})
	keyBlock := []byte("-----BEGIN PRIVATE KEY-----\naGVsbG8=\n-----END PRIVATE KEY-----\n")
	mixed := slices.Concat([]byte("leading junk\n"), pemOf(a.cert), keyBlock, pemOf(b.cert), []byte("trailing junk\n"))

	if got, want := decodePemsByType(mixed, "CERTIFICATE"), slices.Concat(a.cert.Raw, b.cert.Raw); !bytes.Equal(got, want) {
		t.Errorf("CERTIFICATE blocks = %d bytes, want the %d bytes of both certificates", len(got), len(want))
	}
	if got := decodePemsByType(mixed, "PRIVATE KEY"); string(got) != "hello" {
		t.Errorf("PRIVATE KEY blocks = %q, want %q", got, "hello")
	}
	if got := decodePemsByType(mixed, "CRL"); got != nil {
		t.Errorf("CRL blocks = %q, want nil", got)
	}
	if got := decodePemsByType(nil, "CERTIFICATE"); got != nil {
		t.Errorf("empty input = %q, want nil", got)
	}
}

func TestWriteCertCSV(t *testing.T) {
	root := newCert(t, certOpts{cn: "Test Root", isCA: true})
	ecLeaf := newCert(t, certOpts{cn: "ec leaf", parent: root})
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaLeaf := newCert(t, certOpts{cn: "rsa, leaf", parent: root, key: rsaKey})

	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if err := writeCertCSVHeader(w); err != nil {
		t.Fatal(err)
	}
	for _, c := range []*testCert{root, ecLeaf, rsaLeaf} {
		if err := writeCertCSV(w, c.cert); err != nil {
			t.Fatal(err)
		}
	}
	w.Flush()

	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatalf("reading back csv: %s", err)
	}
	day := func(tm time.Time) string { return tm.Format(time.DateOnly) }
	want := [][]string{
		{"CN", "Issuer", "Is CA", "Algo", "SigAlgo", "Bits", "Not Before", "Not After", "Subject"},
		{"Test Root", "Test Root", "true", "ECDSA", "ECDSA-SHA256", "256",
			day(root.cert.NotBefore), day(root.cert.NotAfter), "CN=Test Root,O=whichca test"},
		{"ec leaf", "Test Root", "false", "ECDSA", "ECDSA-SHA256", "256",
			day(ecLeaf.cert.NotBefore), day(ecLeaf.cert.NotAfter), "CN=ec leaf,O=whichca test"},
		{"rsa, leaf", "Test Root", "false", "RSA", "ECDSA-SHA256", "2048",
			day(rsaLeaf.cert.NotBefore), day(rsaLeaf.cert.NotAfter), `CN=rsa\, leaf,O=whichca test`},
	}
	if len(rows) != len(want) {
		t.Fatalf("got %d rows, want %d", len(rows), len(want))
	}
	for i := range want {
		if !slices.Equal(rows[i], want[i]) {
			t.Errorf("row %d:\n got %q\nwant %q", i, rows[i], want[i])
		}
	}
}

package cmd

import (
	"crypto/sha1"
	"encoding/base64"
	"slices"
	"testing"
)

func TestThumb(t *testing.T) {
	a := newCert(t, certOpts{cn: "a", isCA: true})
	b := newCert(t, certOpts{cn: "b", isCA: true})

	sum := sha1.Sum(a.cert.Raw)
	if got, want := thumb(a.cert), base64.RawStdEncoding.EncodeToString(sum[:]); got != want {
		t.Errorf("thumb = %q, want the base64 sha1 %q", got, want)
	}
	if thumb(a.cert) == thumb(b.cert) {
		t.Error("different certificates have the same thumbprint")
	}
}

func TestCullCerts(t *testing.T) {
	p := newTestPKI(t)
	chain := []*testCert{p.leaf, p.inter, p.root}
	certs := func(tcs ...*testCert) []*testCert { return tcs }

	tests := []struct {
		name              string
		exclude, haystack []*testCert
		want              []string
	}{
		{
			name:     "nothing excluded",
			haystack: chain,
			want:     []string{"localhost", "Test Intermediate", "Test Root"},
		},
		{
			name:     "server sent leaf and intermediate",
			exclude:  certs(p.leaf, p.inter),
			haystack: chain,
			want:     []string{"Test Root"},
		},
		{
			name:     "server sent leaf only",
			exclude:  certs(p.leaf),
			haystack: chain,
			want:     []string{"Test Intermediate", "Test Root"},
		},
		{
			// a root is always needed in the bundle, even when the server
			// sends it along.
			name:     "roots are never excluded",
			exclude:  chain,
			haystack: chain,
			want:     []string{"Test Root"},
		},
		{
			name:     "single certificate is returned as is",
			exclude:  certs(p.leaf),
			haystack: certs(p.leaf),
			want:     []string{"localhost"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cullCerts(certsOf(tt.exclude), certsOf(tt.haystack))
			if names := subjects(got); !slices.Equal(names, tt.want) {
				t.Errorf("cullCerts = %v, want %v", names, tt.want)
			}
		})
	}
}

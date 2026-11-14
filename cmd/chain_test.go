package cmd

import (
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestVerifyChains(t *testing.T) {
	p := newTestPKI(t)

	t.Run("complete chain needs nothing fetched", func(t *testing.T) {
		chains, missing, err := verifyChains([]*x509.Certificate{p.leaf.cert, p.inter.cert}, p.roots)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		if len(missing) != 0 {
			t.Errorf("missing = %v, want none", subjects(missing))
		}
		if len(chains) != 1 || len(chains[0]) != 3 {
			t.Fatalf("chains = %v, want one chain of three", chains)
		}
	})

	t.Run("missing intermediate is fetched", func(t *testing.T) {
		chains, missing, err := verifyChains([]*x509.Certificate{p.leaf.cert}, p.roots)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		if got := subjects(missing); !slices.Equal(got, []string{"Test Intermediate"}) {
			t.Errorf("missing = %v, want [Test Intermediate]", got)
		}
		if len(chains) != 1 || !chains[0][2].Equal(p.root.cert) {
			t.Errorf("chains = %v, want one chain ending at the root", chains)
		}
	})

	t.Run("cross signed root", func(t *testing.T) {
		// the chain runs to a root that isn't trusted, whose issuer url
		// serves a copy of itself signed by one that is.  the climb passes
		// through the self signed root on the way up: it gets fetched, but
		// it isn't something anyone needs to install, so it mustn't be
		// reported as missing.  the cross signed copy is.
		old := newCert(t, certOpts{cn: "Old Root", isCA: true, aia: p.aia.URL + "/old-cross.crt"})
		cross := newCert(t, certOpts{cn: "Old Root", isCA: true, key: old.key, parent: p.root})
		inter := newCert(t, certOpts{
			cn:     "Old Intermediate",
			isCA:   true,
			parent: old,
			aia:    p.aia.serve("/old-root.crt", old.cert.Raw),
		})
		leaf := newCert(t, certOpts{
			cn:     "localhost",
			parent: inter,
			aia:    p.aia.serve("/old-inter.crt", inter.cert.Raw),
		})
		p.aia.serve("/old-cross.crt", cross.cert.Raw)

		chains, missing, err := verifyChains([]*x509.Certificate{leaf.cert}, p.roots)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		if len(missing) != 2 || !missing[0].Equal(inter.cert) || !missing[1].Equal(cross.cert) {
			t.Errorf("missing = %v, want the intermediate and the cross signed root only", subjects(missing))
		}
		if len(chains) == 0 || !chains[0][len(chains[0])-1].Equal(p.root.cert) {
			t.Errorf("chains = %v, want a chain ending at the trusted root", chains)
		}
	})

	t.Run("no issuer url", func(t *testing.T) {
		leaf := newCert(t, certOpts{cn: "orphan", parent: p.inter})
		_, _, err := verifyChains([]*x509.Certificate{leaf.cert}, p.roots)
		if !errors.Is(err, ErrNoIssuingCertURL) {
			t.Errorf("err = %v, want ErrNoIssuingCertURL", err)
		}
	})

	t.Run("untrusted root", func(t *testing.T) {
		// the climb fetches the intermediate and then the root, which is self
		// signed and has nowhere further to go.
		_, _, err := verifyChains([]*x509.Certificate{p.leaf.cert}, x509.NewCertPool())
		if !errors.Is(err, ErrNoIssuingCertURL) {
			t.Errorf("err = %v, want ErrNoIssuingCertURL", err)
		}
	})

	t.Run("issuer url not found", func(t *testing.T) {
		leaf := newCert(t, certOpts{cn: "404", parent: p.inter, aia: p.aia.URL + "/nope.crt"})
		_, _, err := verifyChains([]*x509.Certificate{leaf.cert}, p.roots)
		if err == nil || errors.Is(err, ErrNoIssuingCertURL) {
			t.Errorf("err = %v, want a fetch error", err)
		}
	})

	t.Run("issuer url serves garbage", func(t *testing.T) {
		url := p.aia.serve("/garbage.crt", []byte("not a certificate"))
		leaf := newCert(t, certOpts{cn: "garbage", parent: p.inter, aia: url})
		_, _, err := verifyChains([]*x509.Certificate{leaf.cert}, p.roots)
		if err == nil || errors.Is(err, ErrNoIssuingCertURL) {
			t.Errorf("err = %v, want a parse error", err)
		}
	})
}

func TestCheckAddr(t *testing.T) {
	p := newTestPKI(t)
	orphan := newCert(t, certOpts{cn: "localhost", parent: p.inter})

	tests := []struct {
		name        string
		leaf        *testCert
		chain       []*x509.Certificate
		roots       *x509.CertPool
		wantOK      bool
		wantInter   []string
		wantMissing []string
	}{
		{
			name:      "complete chain",
			leaf:      p.leaf,
			chain:     []*x509.Certificate{p.inter.cert},
			roots:     p.roots,
			wantOK:    true,
			wantInter: []string{"Test Intermediate"},
		},
		{
			name:        "leaf only",
			leaf:        p.leaf,
			roots:       p.roots,
			wantMissing: []string{"Test Intermediate"},
		},
		{
			// can't be fixed by fetching, so it's reported as not ok rather
			// than as an error.
			name:  "leaf only without issuer url",
			leaf:  orphan,
			roots: p.roots,
		},
		{
			name:      "untrusted root",
			leaf:      p.leaf,
			chain:     []*x509.Certificate{p.inter.cert},
			roots:     x509.NewCertPool(),
			wantInter: []string{"Test Intermediate"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := tlsServer(t, tt.leaf, tt.chain...)
			ok, leaf, inter, missing, err := checkAddr(addr, tt.roots)
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
			if ok != tt.wantOK {
				t.Errorf("ok = %v, want %v", ok, tt.wantOK)
			}
			if !leaf.Equal(tt.leaf.cert) {
				t.Errorf("leaf = %s, want %s", leaf.Subject, tt.leaf.cert.Subject)
			}
			if got := subjects(inter); !slices.Equal(got, tt.wantInter) {
				t.Errorf("intermediates = %v, want %v", got, tt.wantInter)
			}
			if got := subjects(missing); !slices.Equal(got, tt.wantMissing) {
				t.Errorf("missing = %v, want %v", got, tt.wantMissing)
			}
		})
	}

	t.Run("bad address", func(t *testing.T) {
		if _, _, _, _, err := checkAddr("no-port-here", p.roots); err == nil {
			t.Error("expected an error")
		}
	})
}

func TestProcessAddr(t *testing.T) {
	p := newTestPKI(t)

	t.Run("complete chain needs only the root", func(t *testing.T) {
		addr := tlsServer(t, p.leaf, p.inter.cert)
		certs, err := processAddr(addr, p.roots)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		if got := subjects(certs); !slices.Equal(got, []string{"Test Root"}) {
			t.Errorf("certs = %v, want [Test Root]", got)
		}
	})

	t.Run("leaf only needs intermediate and root", func(t *testing.T) {
		addr := tlsServer(t, p.leaf)
		certs, err := processAddr(addr, p.roots)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		if got := subjects(certs); !slices.Equal(got, []string{"Test Intermediate", "Test Root"}) {
			t.Errorf("certs = %v, want [Test Intermediate Test Root]", got)
		}
	})

	t.Run("untrusted root", func(t *testing.T) {
		addr := tlsServer(t, p.leaf, p.inter.cert)
		if _, err := processAddr(addr, x509.NewCertPool()); err == nil {
			t.Error("expected an error")
		}
	})
}

func TestCheckFile(t *testing.T) {
	p := newTestPKI(t)
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	t.Run("complete chain", func(t *testing.T) {
		ok, leaf, inter, missing, err := checkFile(write("full.pem", pemOf(p.leaf.cert, p.inter.cert)), p.roots)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		if !ok || !leaf.Equal(p.leaf.cert) || len(inter) != 1 || len(missing) != 0 {
			t.Errorf("got ok=%v leaf=%s inter=%v missing=%v", ok, leaf.Subject, subjects(inter), subjects(missing))
		}
	})

	t.Run("leaf only", func(t *testing.T) {
		ok, _, _, missing, err := checkFile(write("leaf.pem", pemOf(p.leaf.cert)), p.roots)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		if ok {
			t.Error("ok = true, want false")
		}
		if got := subjects(missing); !slices.Equal(got, []string{"Test Intermediate"}) {
			t.Errorf("missing = %v, want [Test Intermediate]", got)
		}
	})

	for name, body := range map[string][]byte{
		"empty.pem":    nil,
		"notpem.pem":   []byte("hello"),
		"badcert.pem":  []byte("-----BEGIN CERTIFICATE-----\naGVsbG8=\n-----END CERTIFICATE-----\n"),
		"nonexistent/": nil,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name)
			if name != "nonexistent/" {
				path = write(name, body)
			}
			if _, _, _, _, err := checkFile(path, p.roots); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

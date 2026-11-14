package cmd

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	golog "log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// testCert is a certificate along with the key that can sign for it.
type testCert struct {
	cert *x509.Certificate
	key  crypto.Signer
}

// certOpts tweaks the template newCert builds from.
type certOpts struct {
	cn     string
	isCA   bool
	aia    string // IssuingCertificateURL, empty for none
	parent *testCert
	key    crypto.Signer // reuse a key, e.g. to cross sign a root
}

var serial int64

func newCert(t *testing.T, o certOpts) *testCert {
	t.Helper()
	key := o.key
	if key == nil {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generating key: %s", err)
		}
		key = k
	}
	serial++
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: o.cn, Organization: []string{"whichca test"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if o.isCA {
		tmpl.IsCA = true
		tmpl.BasicConstraintsValid = true
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.DNSNames = []string{"localhost"}
		tmpl.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1)}
	}
	if o.aia != "" {
		tmpl.IssuingCertificateURL = []string{o.aia}
	}
	parent, signer := tmpl, key
	if o.parent != nil {
		parent, signer = o.parent.cert, o.parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key.Public(), signer)
	if err != nil {
		t.Fatalf("creating certificate %s: %s", o.cn, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate %s: %s", o.cn, err)
	}
	return &testCert{cert: cert, key: key}
}

// aiaServer serves DER certificates by path, standing in for the issuer URLs
// found in the authority information access extension.
type aiaServer struct {
	*httptest.Server
	mu    sync.Mutex
	paths map[string][]byte
}

func newAIAServer(t *testing.T) *aiaServer {
	t.Helper()
	s := &aiaServer{paths: map[string][]byte{}}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		body, ok := s.paths[r.URL.Path]
		s.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(body)
	}))
	t.Cleanup(s.Close)
	return s
}

// serve publishes body at path and returns the full URL to it.
func (s *aiaServer) serve(path string, body []byte) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.paths[path] = body
	return s.URL + path
}

// testPKI is a root -> intermediate -> leaf chain, with the leaf and the
// intermediate pointing at an aiaServer for their issuers.
type testPKI struct {
	root, inter, leaf *testCert
	aia               *aiaServer
	roots             *x509.CertPool
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	p := &testPKI{aia: newAIAServer(t)}
	p.root = newCert(t, certOpts{cn: "Test Root", isCA: true})
	p.inter = newCert(t, certOpts{
		cn:     "Test Intermediate",
		isCA:   true,
		parent: p.root,
		aia:    p.aia.URL + "/root.crt",
	})
	p.leaf = newCert(t, certOpts{
		cn:     "localhost",
		parent: p.inter,
		aia:    p.aia.URL + "/inter.crt",
	})
	p.aia.serve("/root.crt", p.root.cert.Raw)
	p.aia.serve("/inter.crt", p.inter.cert.Raw)
	p.roots = x509.NewCertPool()
	p.roots.AddCert(p.root.cert)
	return p
}

// tlsServer starts a TLS listener on loopback that presents chain, leaf
// first, and returns its host:port.
func tlsServer(t *testing.T, leaf *testCert, chain ...*x509.Certificate) string {
	t.Helper()
	raw := [][]byte{leaf.cert.Raw}
	for _, c := range chain {
		raw = append(raw, c.Raw)
	}
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: raw, PrivateKey: leaf.key}},
	}
	// the client hangs up after the handshake, which the server would
	// otherwise log as an error in the middle of the test output.
	srv.Config.ErrorLog = golog.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String()
}

func pemOf(certs ...*x509.Certificate) []byte {
	var b []byte
	for _, c := range certs {
		b = append(b, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return b
}

// subjects returns the common names of certs, for readable comparisons.
func subjects(certs []*x509.Certificate) []string {
	var cns []string
	for _, c := range certs {
		cns = append(cns, c.Subject.CommonName)
	}
	return cns
}

func certsOf(tcs []*testCert) []*x509.Certificate {
	var certs []*x509.Certificate
	for _, tc := range tcs {
		certs = append(certs, tc.cert)
	}
	return certs
}

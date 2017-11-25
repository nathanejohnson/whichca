package cmd

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	golog "log"
	"net/http"
	"os"
	"strings"
)

var (
	log *golog.Logger
)

type MinCACmd struct {
	hostports   stringparams
	files       globparams
	contOnError bool
	f           *flag.FlagSet
	b           *bytes.Buffer
}

func NewMinCACmd() *MinCACmd {
	mca := &MinCACmd{
		f: flag.NewFlagSet("minca", flag.ContinueOnError),
		b: &bytes.Buffer{},
	}
	mca.f.SetOutput(mca.b)
	mca.f.Var(&mca.hostports, "hp", "search `host:port` for ssl chains")
	mca.f.Var(&mca.files, "p", "search `pathspec` for certificate files")
	mca.f.BoolVar(&mca.contOnError, "continue", false, "continue on error")
	log = golog.New(os.Stderr, "", 0)
	return mca
}

func (mca *MinCACmd) Help() string {
	mca.b.Reset()
	mca.f.PrintDefaults()
	return mca.b.String()
}

func (mca *MinCACmd) Run(args []string) int {
	err := mca.f.Parse(args)
	if err != nil || (len(mca.files) == 0 && len(mca.hostports) == 0) {
		return RunResultHelp
	}
	cm := make(map[string]*x509.Certificate)
	for _, file := range mca.files {
		certs, err := processFile(file)
		if err != nil {
			log.Println(err)
			if !mca.contOnError {
				os.Exit(1)
			}
		}
		for _, crt := range certs {
			cm[crt.Subject.CommonName] = crt
		}
	}

	for _, hostport := range mca.hostports {
		certs, err := processAddr(hostport)
		if err != nil {
			log.Println(err)
			if !mca.contOnError {
				os.Exit(1)
			}
		}
		for _, crt := range certs {
			cm[crt.Subject.CommonName] = crt
		}
	}
	for _, cert := range cm {
		fmt.Printf("# %s\n", cert.Subject.CommonName)
		pem.Encode(os.Stdout, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
	}
	return 0
}

func (mca *MinCACmd) Synopsis() string {
	return "return minimum CA bundle for given input"
}

func processAddr(addr string) ([]*x509.Certificate, error) {
	hostport := strings.Split(addr, ":")
	if len(hostport) != 2 {
		return nil, fmt.Errorf("invalid host:port specification: %s", addr)
	}
	var PeerCertificates []*x509.Certificate
	var VerifiedChains [][]*x509.Certificate
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		ServerName:         hostport[0],
		InsecureSkipVerify: true,
		// Mamually verify certs, catch case where intermediates are missing
		// and dowload them.
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no certificates returned from %s", addr)
			}

			PeerCertificates = make([]*x509.Certificate, 0, len(rawCerts))
			for _, raw := range rawCerts {
				cert, err := x509.ParseCertificate(raw)
				if err != nil {
					return fmt.Errorf("error parsing cert from %s: %s", addr, err)
				}
				PeerCertificates = append(PeerCertificates, cert)
			}
			cp := x509.NewCertPool()
			if len(PeerCertificates) > 1 {
				for _, cert := range PeerCertificates[1:] {
					cp.AddCert(cert)
				}
			}
			var err error
			VerifiedChains, err = PeerCertificates[0].Verify(x509.VerifyOptions{
				Intermediates: cp,
			})
			if err != nil {
				var dledIntermediates []*x509.Certificate

				dledIntermediates, err = fetchIntermediates(PeerCertificates[len(PeerCertificates)-1])
				if err != nil {
					return fmt.Errorf("failed to find chain for %s: %s", addr, err)
				}
				cp = x509.NewCertPool()
				for _, cert := range dledIntermediates {
					cp.AddCert(cert)
				}
				VerifiedChains, err = PeerCertificates[0].Verify(x509.VerifyOptions{
					Intermediates: cp,
				})
				if err != nil {
					return fmt.Errorf("chain failed verification after fetch: %s", err)
				}

			}
			return nil
		},
	})
	if err != nil {
		return nil, fmt.Errorf("error connecting to host %s: %s", addr, err)
	}

	conn.Close()
	if len(VerifiedChains) != 1 {
		return nil, fmt.Errorf("weird length of VerifiedChains: %d", len(VerifiedChains))
	}

	return cullCerts(PeerCertificates, VerifiedChains[0]), nil

}

func cullCerts(exclude []*x509.Certificate, haystack []*x509.Certificate) []*x509.Certificate {
	if len(haystack) == 1 {
		return haystack
	}
	skips := make(map[string]bool)
	for _, crt := range exclude {
		// skip roots if passed in as an exclude
		if crt.Issuer.CommonName != crt.Subject.CommonName && crt.Issuer.CommonName != "" {
			skips[crt.Subject.CommonName] = true
		}
	}
	var ret []*x509.Certificate
	for _, crt := range haystack {
		if !skips[crt.Subject.CommonName] {
			ret = append(ret, crt)
		}
	}
	return ret
}

func fetchIntermediates(cert *x509.Certificate) ([]*x509.Certificate, error) {
	origCert := cert
	var retval []*x509.Certificate
	for {
		_, err := cert.Verify(x509.VerifyOptions{})
		if err == nil {
			break
		}
		if len(cert.IssuingCertificateURL) == 0 {
			return nil, fmt.Errorf("failed to fetchintermediates for %s",
				origCert.Subject.CommonName)
		}
		cert, err = fetchCert(cert.IssuingCertificateURL[0])
		if err != nil {
			return nil, fmt.Errorf("error fetching intermediate %s for %s: %s",
				cert.Issuer.CommonName,
				origCert.Subject.CommonName,
				err,
			)
		}
		retval = append(retval, cert)

	}
	return retval, nil
}

func fetchCert(url string) (*x509.Certificate, error) {
	c := http.Client{}
	resp, err := c.Get(url)
	if err != nil {
		return nil, fmt.Errorf("error fetching url %s: %s", url, err)
	}
	defer resp.Body.Close()
	raw, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading respse body for url %s: %s", url, err)
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, fmt.Errorf("error parsing certificate for url %s: %s", url, err)
	}
	return cert, nil
}

func processFile(certfile string) ([]*x509.Certificate, error) {
	fbytes, err := ioutil.ReadFile(certfile)
	if err != nil {
		return nil, fmt.Errorf("error reading file %s: %s", certfile, err)
	}
	certders := decodePemsByType(fbytes, "CERTIFICATE")
	if len(certders) == 0 {
		return nil, fmt.Errorf("no certificates found in passed bundle %s", certfile)
	}
	certs, err := x509.ParseCertificates(certders)
	if err != nil {
		return nil, fmt.Errorf("error parsing certificates for file %s: %s", certfile, err)
	}

	if len(certs) == 0 {
		fmt.Errorf("no proper ASN1 certificate data found in file %s", certfile)
	}

	// We assume first is the certificate, and the remaining ones are intermediates.
	cp := x509.NewCertPool()
	if len(certs) > 1 {
		for _, crt := range certs[1:] {
			cp.AddCert(crt)
		}
	}
	chains, err := certs[0].Verify(x509.VerifyOptions{
		Intermediates: cp,
		Roots:         nil, // use system cert pool
	})

	if err != nil {
		return nil, fmt.Errorf("error on verification of file %s: %s", certfile, err)
	}

	if len(chains) == 0 {
		return nil, fmt.Errorf("Invalid length of chains for file %s: %d", certfile, len(chains))
	}

	var ret []*x509.Certificate
	for _, chain := range chains {
		ret = append(ret, cullCerts(certs, chain)...)
	}
	return ret, nil
}

// Return all decoded pem blocks of a specified type.
func decodePemsByType(PEMblocks []byte, Type string) []byte {
	var blck *pem.Block
	rest := PEMblocks
	var resp []byte
	for {
		blck, rest = pem.Decode(rest)
		if blck == nil {
			break
		}
		if blck.Type == Type {
			resp = append(resp, blck.Bytes...)
		}
	}
	return resp
}

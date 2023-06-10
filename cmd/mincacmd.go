package cmd

import (
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

type MinCACmd struct {
	hostports   stringparams
	files       globparams
	cafile      string
	contOnError bool
	*BaseCmd
}

func NewMinCACmd() *MinCACmd {
	mca := &MinCACmd{
		BaseCmd: &BaseCmd{},
	}
	mca.BaseCmd.Init("minca")
	mca.f.SetOutput(mca.b)
	mca.f.Var(&mca.hostports, "hp", "search `host:port` for ssl chains")
	mca.f.Var(&mca.files, "p", "search `pathspec` for certificate files")
	mca.f.BoolVar(&mca.contOnError, "continue", false, "continue on error")
	mca.f.StringVar(&mca.cafile, "ca", "", "path to a ca bundle.  defaults to the system bundle")
	return mca
}

func (mca *MinCACmd) Run(args []string) int {
	err := mca.f.Parse(args)
	if err != nil || (len(mca.files) == 0 && len(mca.hostports) == 0) {
		return RunResultHelp
	}

	var ca *x509.CertPool
	if mca.cafile != "" {
		_, ca, err = loadCABundle(mca.cafile)
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}
	}

	cm := make(map[string]*x509.Certificate)
	for _, file := range mca.files {
		certs, err := processFile(file, ca)
		if err != nil {
			log.Println(err)
			if !mca.contOnError {
				os.Exit(1)
			}
		}
		for _, crt := range certs {
			cm[thumb(crt)] = crt
		}
	}

	for _, hostport := range mca.hostports {
		certs, err := processAddr(hostport, ca)
		if err != nil {
			log.Println(err)
			if !mca.contOnError {
				os.Exit(1)
			}
		}
		for _, crt := range certs {
			cm[thumb(crt)] = crt
		}
	}
	for _, cert := range cm {
		writeCert(os.Stdout, cert)
	}
	return 0
}

func (mca *MinCACmd) Synopsis() string {
	return "return minimum CA bundle for given input"
}

func processAddr(addr string, ca *x509.CertPool) ([]*x509.Certificate, error) {
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
			var err error
			VerifiedChains, _, err = verifyChains(PeerCertificates, ca)
			if err != nil {
				return err
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

func thumb(cert *x509.Certificate) string {
	return base64.RawStdEncoding.EncodeToString(sha1.New().Sum(cert.Raw))
}

func cullCerts(exclude []*x509.Certificate, haystack []*x509.Certificate) []*x509.Certificate {
	if len(haystack) == 1 {
		return haystack
	}
	skips := make(map[string]bool)
	for _, crt := range exclude {
		// skip roots if passed in as an exclude
		if crt.Issuer.CommonName != crt.Subject.CommonName && crt.Issuer.CommonName != "" {
			skips[thumb(crt)] = true
		}
	}
	var ret []*x509.Certificate
	for _, crt := range haystack {
		if !skips[thumb(crt)] {
			ret = append(ret, crt)
		}
	}
	return ret
}

func processFile(certfile string, ca *x509.CertPool) ([]*x509.Certificate, error) {
	fbytes, err := ioutil.ReadFile(certfile)
	if err != nil {
		return nil, fmt.Errorf("error reading file %s: %w", certfile, err)
	}
	certders := decodePemsByType(fbytes, "CERTIFICATE")
	if len(certders) == 0 {
		return nil, fmt.Errorf("no certificates found in passed bundle %s", certfile)
	}
	certs, err := x509.ParseCertificates(certders)
	if err != nil {
		return nil, fmt.Errorf("error parsing certificates for file %s: %w", certfile, err)
	}

	if len(certs) == 0 {
		fmt.Errorf("no proper ASN1 certificate data found in file %s", certfile)
	}

	chains, _, err := verifyChains(certs, ca)

	if err != nil {
		return nil, fmt.Errorf("error on verification of file %s: %w", certfile, err)
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

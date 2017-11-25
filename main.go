package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	logpkg "log"
	"net/http"
	"os"
	"strings"
)

var (
	log         *logpkg.Logger
	files       globparams
	hostports   stringparams
	contOnError bool
)

func main() {
	log = logpkg.New(os.Stderr, "", 0)
	handleFlags()
	cm := make(map[string]*x509.Certificate)
	for _, file := range files {
		certs, err := processFile(file)
		if err != nil {
			log.Println(err)
			if !contOnError {
				os.Exit(1)
			}
		}
		for _, crt := range certs {
			cm[crt.Subject.CommonName] = crt
		}
	}

	for _, hostport := range hostports {
		certs, err := processAddr(hostport)
		if err != nil {
			log.Println(err)
			if !contOnError {
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
			fmt.Printf("# skipping %s, issuer %s\n", crt.Subject.CommonName, crt.Issuer.CommonName)
			skips[crt.Subject.CommonName] = true
		}
	}
	var ret []*x509.Certificate
	for _, crt := range haystack {
		if !skips[crt.Subject.CommonName] {
			ret = append(ret, crt)
		} else {
			fmt.Printf("# in haystack skipping %s\n", crt.Subject.CommonName)
		}
	}
	return ret
}

// if certs is nil and err nil, none were download but verification succeeded.
// if certs is not nil and err is nil, these intermediates were fetched.
func fetchIntermediates(cert *x509.Certificate) ([]*x509.Certificate, error) {
	origCert := cert
	var retval []*x509.Certificate
	for {
		if len(cert.IssuingCertificateURL) == 0 {
			break
		}
		fmt.Printf("fetching %s", cert.IssuingCertificateURL[0])
		_, err := cert.Verify(x509.VerifyOptions{})
		if err != nil {
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

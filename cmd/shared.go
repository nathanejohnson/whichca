package cmd

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	golog "log"
	"net/http"
)

var (
	log *golog.Logger
)

func loadCABundle(loc string) (*x509.CertPool, error) {
	fBytes, err := ioutil.ReadFile(loc)
	if err != nil {
		return nil, err
	}
	certders := decodePemsByType(fBytes, "CERTIFICATE")
	if len(certders) == 0 {
		return nil, fmt.Errorf("no certificates found in passed bundle %s", loc)
	}
	certs, err := x509.ParseCertificates(certders)
	if err != nil {
		return nil, fmt.Errorf("error parsing certificates for ca bundle: %w", err)
	}
	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
	}
	return pool, nil
}

func writeCert(w io.Writer, cert *x509.Certificate) error {
	_, err := fmt.Fprintf(w, "# %s\n", cert.Subject.CommonName)
	if err != nil {
		return err
	}
	return pem.Encode(w, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}

func verifyChains(certs []*x509.Certificate, ca *x509.CertPool) (chains [][]*x509.Certificate, dledIntermediates []*x509.Certificate, err error) {

	cp := x509.NewCertPool()
	if len(certs) > 1 {
		for _, cert := range certs[1:] {
			cp.AddCert(cert)
		}
	}
	chains, err = certs[0].Verify(x509.VerifyOptions{
		Intermediates: cp,
		Roots:         ca,
	})
	if err != nil {
		dledIntermediates, err = fetchIntermediates(certs[len(certs)-1], ca)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to find chain: %w", err)
		}
		for _, cert := range dledIntermediates {
			cp.AddCert(cert)
		}
		chains, err = certs[0].Verify(x509.VerifyOptions{
			Intermediates: cp,
			Roots:         ca,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("chain failed verification after fetch: %w", err)
		}
	}
	return
}
func fetchIntermediates(cert *x509.Certificate, ca *x509.CertPool) ([]*x509.Certificate, error) {
	origCert := cert
	var retval []*x509.Certificate
	for {
		_, err := cert.Verify(x509.VerifyOptions{
			Roots: ca,
		})
		if err == nil {
			break
		}
		if len(cert.IssuingCertificateURL) == 0 {
			return nil, fmt.Errorf("failed to fetchintermediates for %s",
				origCert.Subject.CommonName)
		}
		cert, err = fetchCert(cert.IssuingCertificateURL[0])
		if err != nil {
			return nil, fmt.Errorf("error fetching intermediate %s for %s: %w",
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
		return nil, fmt.Errorf("error fetching url %s: %w", url, err)
	}
	defer resp.Body.Close()
	raw, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading respse body for url %s: %w", url, err)
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, fmt.Errorf("error parsing certificate for url %s: %w", url, err)
	}
	return cert, nil
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

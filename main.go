package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

var l *log.Logger

func main() {
	l = log.New(os.Stderr, "", 0)
	if len(os.Args) != 2 {
		l.Fatalf("Usage: %s <certificate>", os.Args[0])
	}

	certfile := os.Args[1]
	fbytes, err := ioutil.ReadFile(certfile)
	if err != nil {
		l.Fatalf("Error reading file %s: %s", certfile, err)
	}
	certders := decodePemsByType(fbytes, "CERTIFICATE")
	if len(certders) == 0 {
		l.Fatal("No certificates found in passed bundle")
	}
	certs, err := x509.ParseCertificates(certders)
	if err != nil {
		l.Fatal("Error parsing certificates: ", err)
	}

	if len(certs) == 0 {
		l.Fatal("No proper ASN1 certificate data found")
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
		log.Fatalf("Got error on verification: %s", err)
	}

	if len(chains) != 1 {
		log.Fatalf("Invalid length of chains: %d", len(chains))
	}

	if len(chains[0]) <= len(certs) {
		log.Fatalf("Invalid length of chains[0]: %d", len(chains[0]))
	}
	for _, chaincert := range chains[0][len(certs):] {
		fmt.Printf("# %s\n", chaincert.Subject.CommonName)
		pem.Encode(os.Stdout, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: chaincert.Raw,
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

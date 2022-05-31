package cmd

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"time"
)

func CertPoolSnoopable() (bool, []*x509.Certificate, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "security", "find-certificate", "-a", "-p")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return false, nil, fmt.Errorf("fuck: %w stderr: %s\n", err, stderr.String())
	}
	var certs []*x509.Certificate
	var (
		block *pem.Block
		rest  []byte = stdout.Bytes()
	)
	for {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			// ignore the certs where inner and outer don't match.
			if err != nil {
				if err.Error() == "x509: inner and outer signature algorithm identifiers don't match" {
					fmt.Fprintf(os.Stderr, "# -- warning, the following had an error:\n"+
						"# x509: inner and outer signature algorithm identifiers don't match\n")
					pem.Encode(os.Stderr, block)
					continue
				}
				return false, nil, err
			}
			certs = append(certs, cert)
		}
	}
	return true, certs, nil
}

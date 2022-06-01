package cmd

import (
	"fmt"
	"crypto/x509"
)

func SystemCertPool() ([]*x509.Certificate, error) {
	return nil, fmt.Errorf("windows not supported")
}

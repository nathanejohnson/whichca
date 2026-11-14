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

// systemRootsKeychain holds the roots apple ships.  it isn't on the default
// keychain search list, so it has to be named explicitly.
const systemRootsKeychain = "/System/Library/Keychains/SystemRootCertificates.keychain"

// SystemCertPool returns the CA certificates this machine trusts: the roots
// apple ships, plus any installed into the keychains on the default search
// list.  the latter is where admin and user installed roots land -- MDM,
// corporate filters, debugging proxies -- and leaving them out understates
// what the machine actually trusts.
//
// keychains hold certificates regardless of whether they're trusted, so the
// results are filtered against the platform's trust settings.  set
// includeUntrusted to get everything that's merely present as well.
func SystemCertPool(includeUntrusted bool) ([]*x509.Certificate, error) {
	// two invocations, because naming a keychain replaces the search list
	// rather than adding to it.
	shipped, err := findCertificates(systemRootsKeychain)
	if err != nil {
		return nil, err
	}
	installed, err := findCertificates()
	if err != nil {
		return nil, err
	}

	var trust trustSettings
	if !includeUntrusted {
		if trust, err = loadTrustSettings(); err != nil {
			return nil, err
		}
	}

	var (
		certs []*x509.Certificate
		seen  = make(map[string]bool)
	)
	for _, group := range [][]*x509.Certificate{shipped, installed} {
		for _, cert := range group {
			// the same root often sits in more than one keychain, e.g. a
			// corporate root in both System and login.
			if seen[string(cert.Raw)] {
				continue
			}
			seen[string(cert.Raw)] = true
			// the search list keychains also carry leaf identities -- machine
			// certs, MDM identities, kerberos principals.  those aren't trust
			// anchors and don't belong in a CA bundle.
			if !cert.IsCA {
				continue
			}
			if !includeUntrusted && !trust.trusts(cert) {
				continue
			}
			certs = append(certs, cert)
		}
	}
	return certs, nil
}

// findCertificates shells out to security(1) for the PEM of every certificate
// in the named keychains, or in the default search list when none are named.
func findCertificates(keychains ...string) ([]*x509.Certificate, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	args := append([]string{"find-certificate", "-ap"}, keychains...)
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "security", args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("error running security %v: %w stderr: %s",
			args, err, stderr.String())
	}

	var (
		certs []*x509.Certificate
		block *pem.Block
		rest  = stdout.Bytes()
	)
	for {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			// ignore the certs where inner and outer don't match.
			if err.Error() == "x509: inner and outer signature algorithm identifiers don't match" {
				fmt.Fprintf(os.Stderr, "# -- warning, the following cert had an error:\n# %s\n",
					err.Error())
				pem.Encode(os.Stderr, block)
				continue
			}
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

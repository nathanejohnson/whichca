package cmd

import (
	"crypto/x509"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// cryptENotFound is the error CertEnumCertificatesInStore reports once it has
// walked past the last certificate in the store.  syscall doesn't name it.
const cryptENotFound = 0x80092004

// SystemCertPool returns the certificates in the Windows "ROOT" system store,
// the trusted root CAs.
//
// x509.SystemCertPool is no help here: on windows it returns an empty pool
// flagged as a system pool, which tells Verify to hand the whole job to the
// platform verifier rather than to expose any certificates.  So we enumerate
// the store ourselves, the way the darwin implementation shells out to
// security(1).
//
// Note that windows populates the root store on demand via Windows Update, so
// this returns the roots cached on the machine rather than every root windows
// would ultimately be willing to trust.
//
// includeUntrusted is ignored: the ROOT store holds trust anchors by
// definition, so there is no untrusted remainder to add.
func SystemCertPool(includeUntrusted bool) ([]*x509.Certificate, error) {
	name, err := syscall.UTF16PtrFromString("ROOT")
	if err != nil {
		return nil, fmt.Errorf("error encoding store name: %w", err)
	}
	store, err := syscall.CertOpenSystemStore(0, name)
	if err != nil {
		return nil, fmt.Errorf("error opening ROOT certificate store: %w", err)
	}
	defer syscall.CertCloseStore(store, 0)

	var certs []*x509.Certificate
	var ctx *syscall.CertContext
	for {
		// each call frees the context passed in, so the previous ctx must not
		// be used or freed after this point.
		ctx, err = syscall.CertEnumCertificatesInStore(store, ctx)
		if err != nil {
			if errno, ok := err.(syscall.Errno); ok && errno == cryptENotFound {
				break
			}
			return nil, fmt.Errorf("error enumerating ROOT certificate store: %w", err)
		}
		if ctx == nil {
			break
		}

		// copy out of the store's memory before the next call invalidates it.
		der := make([]byte, ctx.Length)
		copy(der, unsafe.Slice(ctx.EncodedCert, ctx.Length))

		cert, err := x509.ParseCertificate(der)
		if err != nil {
			// the store can hold certs crypto/x509 won't parse.  warn and keep
			// going rather than losing the whole bundle over one bad entry.
			fmt.Fprintf(os.Stderr, "# -- warning, skipping unparseable cert in ROOT store:\n# %s\n", err)
			continue
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

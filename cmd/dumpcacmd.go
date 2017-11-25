package cmd

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	golog "log"
	"os"
	"reflect"
	"unsafe"
)

type DumpCACmd struct {
}

func (dc *DumpCACmd) Synopsis() string {
	return "Dump the system CA cert bundle to stdout with PEM encoding"
}

func (dc *DumpCACmd) Help() string {
	return ""
}

func (dc *DumpCACmd) Run(args []string) int {
	log = golog.New(os.Stderr, "", 0)
	systemCA, err := x509.SystemCertPool()
	if err != nil {
		log.Print("error parsing system CA cert bundle: %s", err)
		return 1
	}

	// eww
	v := reflect.ValueOf(systemCA)
	certsv := v.Elem().FieldByName("certs")
	certs := reflect.NewAt(certsv.Type(),
		unsafe.Pointer(certsv.UnsafeAddr())).
		Elem().
		Interface().([]*x509.Certificate)

	for _, cert := range certs {
		fmt.Printf("# %s\n", cert.Subject.CommonName)

		pem.Encode(os.Stdout, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
	}
	return 0
}

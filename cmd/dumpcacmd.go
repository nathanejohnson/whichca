package cmd

import (
	"crypto/x509"
	"os"
	"reflect"
	"unsafe"
)

type DumpCACmd struct {
	*BaseCmd
}

func NewCumpCACmd() *DumpCACmd {
	dca := &DumpCACmd{
		BaseCmd: &BaseCmd{},
	}
	dca.Init("dumpca")
	return dca
}

func (dc *DumpCACmd) Synopsis() string {
	return "Dump the system CA cert bundle to stdout with PEM encoding"
}


func (dc *DumpCACmd) Run(args []string) int {
	systemCA, err := x509.SystemCertPool()
	if err != nil {
		log.Print("error parsing system CA cert bundle: %s", err)
		return 1
	}

	// eww
	v := reflect.ValueOf(systemCA)
	certsv := v.Elem().FieldByName("certs")
	if certsv.Kind() == reflect.Invalid {
		log.Print("this only works on golang 1.15 and earlier.  sorry :(")
		return 1
	}
	certs := reflect.NewAt(certsv.Type(),
		unsafe.Pointer(certsv.UnsafeAddr())).
		Elem().
		Interface().([]*x509.Certificate)

	for _, cert := range certs {
		writeCert(os.Stdout, cert)
	}
	return 0
}

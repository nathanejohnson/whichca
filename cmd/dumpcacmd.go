package cmd

import (
	"os"
)

type DumpCACmd struct {
	*BaseCmd
}

func NewDumpCACmd() *DumpCACmd {
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
	certs, err := SystemCertPool()
	if err != nil {
		log.Printf("error fetching system cert pool: %s", err)
		return 1
	}
	for _, cert := range certs {
		writeCert(os.Stdout, cert)
	}
	return 0
}

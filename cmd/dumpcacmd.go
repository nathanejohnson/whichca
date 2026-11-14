package cmd

import (
	"encoding/csv"
	"os"
)

type DumpCACmd struct {
	*BaseCmd
	csv       bool
	untrusted bool
}

func NewDumpCACmd() *DumpCACmd {
	dca := &DumpCACmd{
		BaseCmd: &BaseCmd{},
	}
	dca.Init("dumpca")
	dca.f.BoolVar(&dca.csv, "csv", false, "output metadata as csv")
	dca.f.BoolVar(&dca.untrusted, "untrusted", false, "also include certificates that are present in the "+
		"platform's stores but aren't trust anchors.  only macos distinguishes the two")
	return dca
}

func (dc *DumpCACmd) Synopsis() string {
	return "Dump the system CA cert bundle to stdout with PEM encoding"
}

func (dc *DumpCACmd) Run(args []string) int {
	certs, err := SystemCertPool(dc.untrusted)
	if err != nil {
		log.Printf("error fetching system cert pool: %s", err)
		return 1
	}
	var csvWriter *csv.Writer
	if dc.csv {
		csvWriter = csv.NewWriter(os.Stdout)
		err = writeCertCSVHeader(csvWriter)
		if err != nil {
			log.Printf("error writing csv: %s", err)
			return 1
		}
		defer csvWriter.Flush()
	}
	for _, cert := range certs {
		switch dc.csv {
		case true:
			err = writeCertCSV(csvWriter, cert)
		default:
			err = writeCert(os.Stdout, cert)
		}
		if err != nil {
			log.Printf("error writing csv: %s", err)
			return 1
		}
	}

	return 0
}

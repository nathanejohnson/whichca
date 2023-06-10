package cmd

import (
	"encoding/csv"
	"os"
)

type DumpCACmd struct {
	*BaseCmd
	csv bool
}

func NewDumpCACmd() *DumpCACmd {
	dca := &DumpCACmd{
		BaseCmd: &BaseCmd{},
	}
	dca.Init("dumpca")
	dca.f.BoolVar(&dca.csv, "csv", false, "output metadata as csv")
	return dca
}

func (dc *DumpCACmd) Synopsis() string {
	return "Dump the system CA cert bundle to stdout with PEM encoding"
}

func (dc *DumpCACmd) Run(args []string) int {
	err := dc.f.Parse(args)
	if err != nil {
		return RunResultHelp
	}
	certs, err := SystemCertPool()
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

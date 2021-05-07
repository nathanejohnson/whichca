package cmd

import (
	"bytes"
	"flag"
	golog "log"
	"os"
)

type BaseCmd struct {
	f *flag.FlagSet
	b *bytes.Buffer
}

func (bc *BaseCmd) Init(flagName string) {
	bc.f = flag.NewFlagSet(flagName, flag.ContinueOnError)
	bc.b = &bytes.Buffer{}
	log = golog.New(os.Stderr, "", 0)

}

func (bc *BaseCmd) Help() string {
	bc.b.Reset()
	bc.f.PrintDefaults()
	return bc.b.String()
}

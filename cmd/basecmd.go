package cmd

import (
	"flag"
	golog "log"
	"os"
)

type BaseCmd struct {
	f *flag.FlagSet
}

func (bc *BaseCmd) Init(flagName string) {
	bc.f = flag.NewFlagSet(flagName, flag.ContinueOnError)
	log = golog.New(os.Stderr, "", 0)

}

// Flags returns the command's flag set, which main parses before calling Run.
func (bc *BaseCmd) Flags() *flag.FlagSet {
	return bc.f
}

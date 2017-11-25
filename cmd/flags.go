package cmd

import (
	"path/filepath"
	"strings"
)

const (
	// We mirror the github.com/mitchellh/cli constant here
	// to decouple this package from the cli package, even
	// though our main requires it.
	RunResultHelp = -18511
)

type globparams []string

func (gp *globparams) Set(v string) error {

	// check for comma separated list
	commas := strings.Split(v, ",")

	for _, c := range commas {
		globs, err := filepath.Glob(c)
		if err == filepath.ErrBadPattern {
			return err
		}
		*gp = append(*gp, globs...)
	}
	return nil
}

func (gp *globparams) String() string {
	return ""
}

type stringparams []string

func (sp *stringparams) Set(v string) error {
	// check for comma separated list
	commas := strings.Split(v, ",")

	*sp = append(*sp, commas...)
	return nil
}

func (sp *stringparams) String() string {
	return ""
}

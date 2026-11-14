package cmd

import (
	"path/filepath"
	"strings"
)

const (
	// RunResultHelp is returned from Run to have main print
	// the command's help text.
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

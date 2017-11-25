// +build !windows

package main

import (
	"github.com/mitchellh/cli"
	"github.com/nathanejohnson/whichca/cmd"
)

func system_specific_cmds(cmds map[string]cli.CommandFactory) {
	cmds["dumpca"] = func() (cli.Command, error) {
		return &cmd.DumpCACmd{}, nil
	}
}

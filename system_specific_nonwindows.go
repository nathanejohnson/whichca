//go:build !windows
// +build !windows

package main

import (
	"github.com/mitchellh/cli"

	"github.com/nathanejohnson/whichca/cmd"
)

func systemSpecificCmds(cmds map[string]cli.CommandFactory) {
	cmds["dumpca"] = func() (cli.Command, error) {
		return cmd.NewCumpCACmd(), nil
	}
}

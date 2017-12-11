package main

import (
	logpkg "log"
	"os"

	"github.com/mitchellh/cli"
	"github.com/nathanejohnson/whichca/cmd"
)

func main() {
	log := logpkg.New(os.Stdout, "", 0)
	c := cli.NewCLI(os.Args[0], "")
	c.Commands = map[string]cli.CommandFactory{
		"minca": func() (cli.Command, error) {
			return cmd.NewMinCACmd(), nil
		},
	}
	systemSpecificCmds(c.Commands)
	c.Args = os.Args[1:]
	errno, err := c.Run()
	if err != nil {
		log.Printf("Error: %s", err)
	}
	os.Exit(errno)
}

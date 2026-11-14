package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"sort"

	"github.com/nathanejohnson/whichca/cmd"
)

var version = ""

type command interface {
	Synopsis() string
	Flags() *flag.FlagSet
	Run(args []string) int
}

var commands = map[string]func() command{
	"minca":   func() command { return cmd.NewMinCACmd() },
	"check":   func() command { return cmd.NewCheckIntermediateCmd() },
	"fetchca": func() command { return cmd.NewFetchCACmd() },
	"dumpca":  func() command { return cmd.NewDumpCACmd() },
	"x509":    func() command { return cmd.NewX509Cmd() },
}

func main() {
	bi, ok := debug.ReadBuildInfo()
	if ok && version == "" {
		version = bi.Main.Version
	}
	os.Exit(run(os.Args[0], os.Args[1:]))
}

func run(name string, args []string) int {
	var showVersion bool
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.BoolVar(&showVersion, "version", false, "print the version and exit")
	fs.BoolVar(&showVersion, "v", false, "shorthand for -version")
	fs.Usage = func() { usage(fs.Output(), fs) }
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 127
	}
	if showVersion {
		fmt.Println(version)
		return 0
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return 127
	}

	cmdName := fs.Arg(0)
	factory, ok := commands[cmdName]
	if !ok {
		fmt.Fprintf(fs.Output(), "Unknown command: %s\n\n", cmdName)
		fs.Usage()
		return 127
	}
	c := factory()
	cfs := c.Flags()
	cfs.Usage = func() {
		fmt.Fprintf(cfs.Output(), "Usage: %s %s [options]\n\n%s\n\n", name, cmdName, c.Synopsis())
		cfs.PrintDefaults()
	}
	if err := cfs.Parse(fs.Args()[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 1
	}
	rc := c.Run(cfs.Args())
	if rc == cmd.RunResultHelp {
		cfs.Usage()
		return 1
	}
	return rc
}

func usage(w io.Writer, fs *flag.FlagSet) {
	names := make([]string, 0, len(commands))
	width := 0
	for n := range commands {
		names = append(names, n)
		width = max(width, len(n))
	}
	sort.Strings(names)

	fmt.Fprintf(w, "Usage: %s [options] <command> [<args>]\n\n", fs.Name())
	fmt.Fprintln(w, "Available commands are:")
	for _, n := range names {
		fmt.Fprintf(w, "    %-*s    %s\n", width, n, commands[n]().Synopsis())
	}
	fmt.Fprintln(w, "\nOptions:")
	fs.PrintDefaults()
}

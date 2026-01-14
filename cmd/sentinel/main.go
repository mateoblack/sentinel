package main

import (
	"os"

	"github.com/alecthomas/kingpin/v2"
	"github.com/byteness/aws-vault/v7/cli"
)

// Version is provided at compile time
var Version = "dev"

func main() {
	app := kingpin.New("sentinel", "Intent-aware access control for AWS credentials")
	app.Version(Version)

	cli.ConfigureSentinelGlobals(app)

	kingpin.MustParse(app.Parse(os.Args[1:]))
}

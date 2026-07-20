// Command cvetrace is the entrypoint for the cvetrace CLI -- see
// internal/cli for the actual argument parsing and orchestration logic.
//
// Go note: "package main" combined with a func main() is what makes a Go
// program a runnable executable rather than an importable library. Every
// other package in this project lives under internal/ specifically so it
// *can't* accidentally become another "package main" -- there's exactly one
// entrypoint, right here.
package main

import (
	"os"

	"github.com/jjuhric/cvetrace-go/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args))
}

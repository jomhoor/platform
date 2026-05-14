package main

import (
	"os"

	"github.com/jomhoor/sso-svc/internal/cli"
)

func main() {
	if !cli.Run(os.Args) {
		os.Exit(1)
	}
}

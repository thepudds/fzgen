// Command fzgen automatically generates fuzz functions.
//
// See the project README for additional information:
//     https://github.com/thepudds/fzgen
package main

import (
	"os"

	"github.com/thepudds/fzgen/gen"
)

func main() {
	os.Exit(gen.FzgenMain())
}

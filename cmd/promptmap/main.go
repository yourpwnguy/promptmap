// Command promptmap is the single binary entry point.
//
// Basically main does three things: build the cobra tree, run it,
// and map the result to a CI friendly exit code (0 clean, 2 hits,
// 1 error). All real logic lives in internal packages, main stays thin.
package main

import (
	"fmt"
	"os"
)

func main() {
	code, err := Execute()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	os.Exit(code)
}

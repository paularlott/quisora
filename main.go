package main

import (
	"context"
	"fmt"
	"os"

	"github.com/paularlott/quisora/cmd"
)

func main() {
	if err := cmd.Root().Execute(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

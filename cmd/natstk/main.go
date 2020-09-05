package main

import (
	"fmt"
	"os"

	"github.com/variadico/natstk/internal/command"
)

func main() {
	if err := command.Root().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "natstk:", err)
		os.Exit(1)
	}
}

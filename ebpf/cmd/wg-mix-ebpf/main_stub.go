//go:build !linux

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "wg-mix-ebpf only supports Linux")
	os.Exit(1)
}

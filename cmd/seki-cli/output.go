package main

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"
)

// printJSON marshals v as indented JSON and writes it to stdout.
func printJSON(v interface{}) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// tableWriter returns a new tabwriter aligned on tabs.
func tableWriter() *tabwriter.Writer {
	return tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
}

// fatalf prints a formatted error to stderr and exits with code 1.
func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}

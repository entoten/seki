package logging

import (
	"io"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
)

// LevelVar holds the current log level atomically, allowing runtime updates
// without restarting the process.
var globalLevel atomic.Pointer[slog.LevelVar]

// Setup creates a new *slog.Logger with the given level and format, and sets
// it as the default logger. The level string should be one of:
// debug, info, warn, error (case-insensitive). The format string should be
// "json" or "text" (case-insensitive); defaults to json.
func Setup(level string, format string) *slog.Logger {
	lvl := ParseLevel(level)
	levelVar := &slog.LevelVar{}
	levelVar.Set(lvl)
	globalLevel.Store(levelVar)

	return newLogger(levelVar, format, os.Stdout)
}

// newLogger creates a logger writing to the given writer. Extracted for testing.
func newLogger(levelVar *slog.LevelVar, format string, w io.Writer) *slog.Logger {
	opts := &slog.HandlerOptions{
		Level: levelVar,
	}

	var handler slog.Handler
	switch strings.ToLower(format) {
	case "text":
		handler = slog.NewTextHandler(w, opts)
	default:
		handler = slog.NewJSONHandler(w, opts)
	}

	logger := slog.New(handler)
	slog.SetDefault(logger)
	return logger
}

// SetLevel updates the global log level at runtime. This is safe to call
// concurrently and takes effect immediately.
func SetLevel(level string) {
	if lv := globalLevel.Load(); lv != nil {
		lv.Set(ParseLevel(level))
	}
}

// ParseLevel converts a string level name to slog.Level.
func ParseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

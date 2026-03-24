package logging

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"
)

func TestSetupJSON(t *testing.T) {
	var buf bytes.Buffer
	levelVar := &slog.LevelVar{}
	levelVar.Set(slog.LevelInfo)
	logger := newLogger(levelVar, "json", &buf)

	logger.Info("hello", "key", "value")

	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %s", err, buf.String())
	}
	if m["msg"] != "hello" {
		t.Errorf("expected msg=hello, got %v", m["msg"])
	}
	if m["key"] != "value" {
		t.Errorf("expected key=value, got %v", m["key"])
	}
}

func TestSetupText(t *testing.T) {
	var buf bytes.Buffer
	levelVar := &slog.LevelVar{}
	levelVar.Set(slog.LevelInfo)
	logger := newLogger(levelVar, "text", &buf)

	logger.Info("text message")

	output := buf.String()
	if len(output) == 0 {
		t.Fatal("expected non-empty text output")
	}
	// Text format should NOT be valid JSON.
	var m map[string]any
	if err := json.Unmarshal([]byte(output), &m); err == nil {
		t.Error("expected text output to not be valid JSON, but it parsed")
	}
}

func TestParseLevel(t *testing.T) {
	tests := []struct {
		input string
		want  slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"DEBUG", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"warning", slog.LevelWarn},
		{"error", slog.LevelError},
		{"unknown", slog.LevelInfo},
		{"", slog.LevelInfo},
	}
	for _, tt := range tests {
		got := ParseLevel(tt.input)
		if got != tt.want {
			t.Errorf("ParseLevel(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestSetLevel(t *testing.T) {
	var buf bytes.Buffer
	levelVar := &slog.LevelVar{}
	levelVar.Set(slog.LevelInfo)
	globalLevel.Store(levelVar)
	logger := newLogger(levelVar, "json", &buf)

	// Debug should be suppressed at info level.
	logger.Debug("should not appear")
	if buf.Len() != 0 {
		t.Error("debug message should be suppressed at info level")
	}

	// Change level to debug.
	SetLevel("debug")

	logger.Debug("should appear")
	if buf.Len() == 0 {
		t.Error("debug message should appear after SetLevel(debug)")
	}
}

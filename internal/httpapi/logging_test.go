package httpapi

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

func TestParseLoggingLevelAcceptsSupportedValues(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  LoggingLevel
	}{
		{value: "debug", want: LoggingLevelDebug},
		{value: "INFO", want: LoggingLevelInfo},
		{value: " warn ", want: LoggingLevelWarn},
		{value: "error", want: LoggingLevelError},
	} {
		got, err := ParseLoggingLevel(tc.value)
		if err != nil {
			t.Fatalf("ParseLoggingLevel(%q) returned error: %v", tc.value, err)
		}
		if got != tc.want {
			t.Fatalf("ParseLoggingLevel(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}
}

func TestParseLoggingLevelRejectsUnsupportedValue(t *testing.T) {
	if _, err := ParseLoggingLevel("trace"); err == nil {
		t.Fatal("ParseLoggingLevel(\"trace\") returned nil error")
	}
}

func TestLoggingLevelFiltersLowerSeverityLogs(t *testing.T) {
	var buf bytes.Buffer
	previousOutput := log.Writer()
	previousFlags := log.Flags()
	previousLevel := currentLoggingLevel.Load()
	log.SetOutput(&buf)
	log.SetFlags(0)
	defer func() {
		log.SetOutput(previousOutput)
		log.SetFlags(previousFlags)
		currentLoggingLevel.Store(previousLevel)
	}()

	SetLoggingLevel(LoggingLevelWarn)

	logInfof("hidden")
	logWarnf("shown")

	output := buf.String()
	if strings.Contains(output, "hidden") {
		t.Fatalf("info log was emitted at warn level: %q", output)
	}
	if !strings.Contains(output, "WARN shown") {
		t.Fatalf("warn log was not emitted at warn level: %q", output)
	}
}

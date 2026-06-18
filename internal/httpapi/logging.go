package httpapi

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync/atomic"
)

type LoggingLevel int32

const (
	LoggingLevelDebug LoggingLevel = iota
	LoggingLevelInfo
	LoggingLevelWarn
	LoggingLevelError
)

var currentLoggingLevel atomic.Int32

func init() {
	currentLoggingLevel.Store(int32(LoggingLevelInfo))
}

func ParseLoggingLevel(value string) (LoggingLevel, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "debug":
		return LoggingLevelDebug, nil
	case "info":
		return LoggingLevelInfo, nil
	case "warn":
		return LoggingLevelWarn, nil
	case "error":
		return LoggingLevelError, nil
	default:
		return LoggingLevelInfo, fmt.Errorf("logging level must be one of debug, info, warn, error")
	}
}

func SetLoggingLevel(level LoggingLevel) {
	currentLoggingLevel.Store(int32(level))
}

func logDebugf(format string, args ...any) {
	logf(LoggingLevelDebug, "DEBUG", format, args...)
}

func logInfof(format string, args ...any) {
	logf(LoggingLevelInfo, "INFO", format, args...)
}

func logWarnf(format string, args ...any) {
	logf(LoggingLevelWarn, "WARN", format, args...)
}

func logErrorf(format string, args ...any) {
	logf(LoggingLevelError, "ERROR", format, args...)
}

func LogInfof(format string, args ...any) {
	logInfof(format, args...)
}

func LogWarnf(format string, args ...any) {
	logWarnf(format, args...)
}

func LogErrorf(format string, args ...any) {
	logErrorf(format, args...)
}

func LogFatalf(format string, args ...any) {
	logErrorf(format, args...)
	os.Exit(1)
}

func logf(level LoggingLevel, label, format string, args ...any) {
	if level < LoggingLevel(currentLoggingLevel.Load()) {
		return
	}
	log.Printf("%s "+format, append([]any{label}, args...)...)
}

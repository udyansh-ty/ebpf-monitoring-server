package logger

import (
	"io"
	"log"
	"os"
)

// LogLevel represents different logging levels
type LogLevel int

const (
	INFO LogLevel = iota
	DEBUG
)

// Logger wraps the standard logger with level support
type Logger struct {
	level  LogLevel
	logger *log.Logger
}

// Global logger instance
var defaultLogger *Logger

func init() {
	defaultLogger = New(INFO)
}

// New creates a new logger with the specified level
func New(level LogLevel) *Logger {
	return &Logger{
		level:  level,
		logger: log.New(os.Stdout, "", log.LstdFlags),
	}
}

// SetLevel sets the logging level for the default logger
func SetLevel(level LogLevel) {
	defaultLogger.level = level
}

// SetDebug enables debug logging for the default logger
func SetDebug() {
	SetLevel(DEBUG)
}

// Info logs an info message
func Info(v ...interface{}) {
	defaultLogger.logger.Print(v...)
}

// Infof logs a formatted info message
func Infof(format string, v ...interface{}) {
	defaultLogger.logger.Printf(format, v...)
}

// Warn logs a warning message
func Warn(v ...interface{}) {
	args := append([]interface{}{"[WARN] "}, v...)
	defaultLogger.logger.Print(args...)
}

// Warnf logs a formatted warning message
func Warnf(format string, v ...interface{}) {
	defaultLogger.logger.Printf("[WARN] "+format, v...)
}

// Debug logs a debug message (only when debug level is enabled)
func Debug(v ...interface{}) {
	if defaultLogger.level >= DEBUG {
		args := append([]interface{}{"[DEBUG] "}, v...)
		defaultLogger.logger.Print(args...)
	}
}

// Debugf logs a formatted debug message (only when debug level is enabled)
func Debugf(format string, v ...interface{}) {
	if defaultLogger.level >= DEBUG {
		defaultLogger.logger.Printf("[DEBUG] "+format, v...)
	}
}

// Fatal logs a fatal message and exits
func Fatal(v ...interface{}) {
	defaultLogger.logger.Fatal(v...)
}

// Fatalf logs a formatted fatal message and exits
func Fatalf(format string, v ...interface{}) {
	defaultLogger.logger.Fatalf(format, v...)
}

// Error logs an error message
func Error(v ...interface{}) {
	args := append([]interface{}{"[ERROR] "}, v...)
	defaultLogger.logger.Print(args...)
}

// Errorf logs a formatted error message
func Errorf(format string, v ...interface{}) {
	defaultLogger.logger.Printf("[ERROR] "+format, v...)
}

// IsDebugEnabled returns true if debug logging is enabled
func IsDebugEnabled() bool {
	return defaultLogger.level >= DEBUG
}

// GetDefaultLogger returns the default logger instance
// Used for passing to components that need a logger
func GetDefaultLogger() *Logger {
	return defaultLogger
}

// Debugf logs a formatted debug message using the logger instance
// Method version to support instances that hold a logger field
func (l *Logger) Debugf(format string, v ...interface{}) {
	if l.level >= DEBUG {
		l.logger.Printf("[DEBUG] "+format, v...)
	}
}

// ANCHOR: File logging support for aggregator debugging - March 21, 2026
// WHY: Enable persistent log file at /var/log/ebpf-aggregator.log for debugging data insertions
// WHAT: InitFileLogger opens file and redirects logging to both stdout and file via io.MultiWriter
// HOW: Replace default logger's writer with MultiWriter(stdout, file) for dual output

// InitFileLogger initializes file logging for the default logger
// Logs will be written to both stdout and the specified file
// Returns error if file cannot be opened (e.g., permissions), but doesn't fail startup
func InitFileLogger(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	w := io.MultiWriter(os.Stdout, f)
	defaultLogger.logger = log.New(w, "", log.LstdFlags)
	return nil
}

// Method variants to support logger instances (for compatibility with storage packages)

// Infof logs a formatted info message using the logger instance
func (l *Logger) Infof(format string, v ...interface{}) {
	l.logger.Printf(format, v...)
}

// Errorf logs a formatted error message using the logger instance
func (l *Logger) Errorf(format string, v ...interface{}) {
	l.logger.Printf("[ERROR] "+format, v...)
}

// Warnf logs a formatted warning message using the logger instance
func (l *Logger) Warnf(format string, v ...interface{}) {
	l.logger.Printf("[WARN] "+format, v...)
}

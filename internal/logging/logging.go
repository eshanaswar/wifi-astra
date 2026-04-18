package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
	"wifi-astra/pkg/constants"
)

var Logger *slog.Logger

// cleanConsoleHandler writes human-readable log lines to stdout.
// Format: [LEVEL] message  — no timestamps, no key=value noise.
type cleanConsoleHandler struct {
	mu    sync.Mutex
	level slog.Level
}

func (h *cleanConsoleHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

func (h *cleanConsoleHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	var prefix string
	switch r.Level {
	case slog.LevelDebug:
		prefix = constants.ThemeInfo + "[DEBUG]" + constants.ColorReset
	case slog.LevelInfo:
		prefix = constants.ThemeInfo + "[INFO]" + constants.ColorReset
	case slog.LevelWarn:
		prefix = constants.ThemeMedium + "[WARN]" + constants.ColorReset
	case slog.LevelError:
		prefix = constants.ThemeCritical + "[ERROR]" + constants.ColorReset
	default:
		prefix = "[LOG]"
	}
	fmt.Printf("%s %s\n", prefix, r.Message)
	return nil
}

func (h *cleanConsoleHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *cleanConsoleHandler) WithGroup(_ string) slog.Handler      { return h }

// multiHandler fans out a single log record to two handlers.
type multiHandler struct {
	console slog.Handler
	file    slog.Handler
}

func (h *multiHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.console.Enabled(ctx, level) || h.file.Enabled(ctx, level)
}

func (h *multiHandler) Handle(ctx context.Context, r slog.Record) error {
	if h.console.Enabled(ctx, r.Level) {
		_ = h.console.Handle(ctx, r)
	}
	if h.file.Enabled(ctx, r.Level) {
		_ = h.file.Handle(ctx, r)
	}
	return nil
}

func (h *multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &multiHandler{
		console: h.console.WithAttrs(attrs),
		file:    h.file.WithAttrs(attrs),
	}
}

func (h *multiHandler) WithGroup(name string) slog.Handler {
	return &multiHandler{
		console: h.console.WithGroup(name),
		file:    h.file.WithGroup(name),
	}
}

// InitLogger initializes a structured logger that writes clean output to stdout
// and full structured output to a master log file.
func InitLogger(logDir string, verbose bool) error {
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return err
	}

	masterLogPath := filepath.Join(logDir, "master.log")

	// Basic Log Rotation: If master.log > 10MB, rotate it
	if info, err := os.Stat(masterLogPath); err == nil && info.Size() > 10*1024*1024 {
		rotatedPath := masterLogPath + "." + time.Now().Format("20060102-150405")
		os.Rename(masterLogPath, rotatedPath)
	}

	logFile, err := os.OpenFile(masterLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}

	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}

	// Console: clean [LEVEL] message format
	consoleH := &cleanConsoleHandler{level: level}

	// File: full structured text with timestamps
	fileH := slog.NewTextHandler(logFile, &slog.HandlerOptions{
		Level: slog.LevelDebug, // always capture everything in the file
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.Attr{Key: a.Key, Value: slog.StringValue(time.Now().Format("2006-01-02 15:04:05"))}
			}
			return a
		},
	})

	Logger = slog.New(&multiHandler{console: consoleH, file: fileH})
	slog.SetDefault(Logger)
	return nil
}

func Info(msg string, args ...any) {
	formattedMsg := fmt.Sprintf(msg, args...)
	if Logger != nil {
		Logger.Info(formattedMsg)
	} else {
		fmt.Printf("%s[INFO]%s %s\n", constants.ThemeInfo, constants.ColorReset, formattedMsg)
	}
}

func Error(msg string, args ...any) {
	formattedMsg := fmt.Sprintf(msg, args...)
	if Logger != nil {
		Logger.Error(formattedMsg)
	} else {
		fmt.Printf("%s[ERROR]%s %s\n", constants.ThemeCritical, constants.ColorReset, formattedMsg)
	}
}

func Success(msg string, args ...any) {
	formattedMsg := fmt.Sprintf(msg, args...)
	fmt.Printf("%s[✓]%s %s\n", constants.ThemeSuccess, constants.ColorReset, formattedMsg)
	if Logger != nil {
		Logger.Info("[✓] " + formattedMsg)
	}
}

func Warn(msg string, args ...any) {
	formattedMsg := fmt.Sprintf(msg, args...)
	if Logger != nil {
		Logger.Warn(formattedMsg)
	} else {
		fmt.Printf("%s[WARN]%s %s\n", constants.ThemeMedium, constants.ColorReset, formattedMsg)
	}
}

func Debug(msg string, args ...any) {
	formattedMsg := fmt.Sprintf(msg, args...)
	if Logger != nil {
		Logger.Debug(formattedMsg)
	}
}

// SetConsoleLevel changes the minimum level written to stdout at runtime.
// Useful for suppressing info noise during module execution.
func SetConsoleLevel(level slog.Level) {
	if h, ok := Logger.Handler().(*multiHandler); ok {
		if ch, ok := h.console.(*cleanConsoleHandler); ok {
			ch.mu.Lock()
			ch.level = level
			ch.mu.Unlock()
		}
	}
}

// Discard replaces the logger with a no-op so tests that don't call
// InitLogger don't panic on nil Logger.
func Discard() {
	Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
}

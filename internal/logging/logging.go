package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"
	"wifi-astra/pkg/constants"
)

var Logger *slog.Logger

// InitLogger initializes a structured logger that writes to both stdout and a master log file.
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

	// Multi-writer for both console and file
	mw := io.MultiWriter(os.Stdout, logFile)

	handler := slog.NewTextHandler(mw, &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.Attr{Key: a.Key, Value: slog.StringValue(time.Now().Format("2006-01-02 15:04:05"))}
			}
			return a
		},
	})

	Logger = slog.New(handler)
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
	if Logger != nil {
		Logger.Info("[✓] " + formattedMsg)
	} else {
		fmt.Printf("%s[✓]%s %s\n", constants.ThemeSuccess, constants.ColorReset, formattedMsg)
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
	} else {
		// Silent by default if no logger
	}
}

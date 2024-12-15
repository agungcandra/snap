package logger

import (
	"context"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	once   sync.Once
	logger *Logger
)

// Logger provide wrapper for zap logging library for appending context
// needed for the application to help debug and find issues within service
type Logger struct {
	logger *zap.Logger
}

// NewLogger construct new Logger using default configuration of zap logger
func NewLogger() *Logger {
	logger, err := zap.NewProduction()
	if err != nil {
		panic(err)
	}

	return &Logger{
		logger: logger,
	}
}

// GetLogger provide singleton implementation for get Logger instance
func GetLogger() *Logger {
	once.Do(func() {
		logger = NewLogger()
	})

	return logger
}

func (l Logger) Error(message string, fields ...zapcore.Field) {
	fields = append(fields, zap.StackSkip("stacktrace", 2))
	l.logger.Error(message, fields...)
}

func ErrorWithContext(ctx context.Context, err error, fields ...zapcore.Field) {
	GetLogger().Error(err.Error(), fields...)
}

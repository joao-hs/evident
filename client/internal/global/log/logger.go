package log

import (
	"os"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Logger interface {
	// Implemented by zap.SugaredLogger

	// Spaces are added between arguments when neither is a string.

	Debug(args ...any)
	Info(args ...any)
	Warn(args ...any)
	Error(args ...any)
	DPanic(args ...any)
	Panic(args ...any)
	Fatal(args ...any)

	// Formats message according to a format specifier.

	Debugf(template string, args ...any)
	Infof(template string, args ...any)
	Warnf(template string, args ...any)
	Errorf(template string, args ...any)
	DPanicf(template string, args ...any)
	Panicf(template string, args ...any)
	Fatalf(template string, args ...any)

	// Spaces are always added between arguments.

	Debugln(args ...any)
	Infoln(args ...any)
	Warnln(args ...any)
	Errorln(args ...any)
	DPanicln(args ...any)
	Panicln(args ...any)
	Fatalln(args ...any)

	SetDebugLevel()
}

type logger struct {
	*zap.SugaredLogger
	level zap.AtomicLevel
}

var (
	log  Logger
	once sync.Once
)

func Get() Logger {
	once.Do(func() {
		log = initLogger()
	})
	return log
}

func initLogger() Logger {
	level := zap.NewAtomicLevelAt(zapcore.InfoLevel)

	fileEncoderConfig := zap.NewProductionEncoderConfig()
	fileEncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	fileEncoder := zapcore.NewJSONEncoder(fileEncoderConfig)

	consoleEncoderConfig := zap.NewDevelopmentEncoderConfig()
	consoleEncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	consoleEncoder := zapcore.NewConsoleEncoder(consoleEncoderConfig)

	infoConsoleEncoderConfig := zapcore.EncoderConfig{
		MessageKey: "msg",
	}
	infoConsoleEncoder := zapcore.NewConsoleEncoder(infoConsoleEncoderConfig)

	cores := []zapcore.Core{
		zapcore.NewCore(
			fileEncoder,
			GetLogFileSyncer(),
			zap.DebugLevel,
		),

		zapcore.NewCore(
			infoConsoleEncoder,
			zapcore.Lock(os.Stdout),
			zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
				return lvl == zap.InfoLevel
			}),
		),

		zapcore.NewCore(
			consoleEncoder,
			zapcore.Lock(os.Stdout),
			zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
				return lvl >= level.Level() && lvl < zapcore.InfoLevel
			}),
		),

		zapcore.NewCore(
			consoleEncoder,
			zapcore.Lock(os.Stderr),
			zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
				return lvl >= level.Level() && lvl >= zap.WarnLevel
			}),
		),
	}

	combinedCore := zapcore.NewTee(cores...)

	log := zap.New(
		combinedCore,
		zap.AddCaller(),
		zap.AddStacktrace(zap.ErrorLevel),
	)

	return &logger{
		SugaredLogger: log.Sugar(),
		level:         level,
	}
}

func (l *logger) SetDebugLevel() {
	l.level.SetLevel(zap.DebugLevel)
}

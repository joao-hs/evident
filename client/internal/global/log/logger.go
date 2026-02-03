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

	Debug(args ...interface{})
	Info(args ...interface{})
	Warn(args ...interface{})
	Error(args ...interface{})
	DPanic(args ...interface{})
	Panic(args ...interface{})
	Fatal(args ...interface{})

	// Formats message according to a format specifier.

	Debugf(template string, args ...interface{})
	Infof(template string, args ...interface{})
	Warnf(template string, args ...interface{})
	Errorf(template string, args ...interface{})
	DPanicf(template string, args ...interface{})
	Panicf(template string, args ...interface{})
	Fatalf(template string, args ...interface{})

	// Spaces are always added between arguments.

	Debugln(args ...interface{})
	Infoln(args ...interface{})
	Warnln(args ...interface{})
	Errorln(args ...interface{})
	DPanicln(args ...interface{})
	Panicln(args ...interface{})
	Fatalln(args ...interface{})

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

	cores := []zapcore.Core{
		zapcore.NewCore(
			fileEncoder,
			GetLogFileSyncer(),
			zap.DebugLevel,
		),

		zapcore.NewCore(
			consoleEncoder,
			zapcore.Lock(os.Stdout),
			zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
				return lvl >= level.Level() && lvl <= zapcore.InfoLevel
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

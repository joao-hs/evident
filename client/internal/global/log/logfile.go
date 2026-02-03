package log

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"go.uber.org/zap/zapcore"
)

type DynamicFileSyncer struct {
	mu             sync.RWMutex
	currentWritter io.WriteCloser
}

func (s *DynamicFileSyncer) Write(p []byte) (n int, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.currentWritter == nil {
		return 0, nil
	}

	return s.currentWritter.Write(p)
}

func (s *DynamicFileSyncer) Sync() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.currentWritter == nil {
		return nil
	}
	if syncer, ok := s.currentWritter.(zapcore.WriteSyncer); ok {
		return syncer.Sync()
	}
	return nil
}

func (s *DynamicFileSyncer) Swap(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	newWritter, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0664)
	if err != nil {
		return err
	}

	oldWriter := s.currentWritter
	s.currentWritter = newWritter

	if oldWriter != nil {
		return oldWriter.Close()
	}

	return nil
}

var (
	dynamicSyncer *DynamicFileSyncer
	syncerOnce    sync.Once
)

func GetLogFileSyncer() *DynamicFileSyncer {
	syncerOnce.Do(func() {
		var logPath string
		if os.Geteuid() == 0 {
			logPath = "/var/log/evident-client.log"
		} else {
			logPath = filepath.Join(os.TempDir(), "evident-client.log")
		}

		// Ensure the directory exists
		err := os.MkdirAll(filepath.Dir(logPath), 0755)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error creating log directory: %s\n", err.Error())
			os.Exit(1)
		}

		// Open the log file
		logFile, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0664)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error while opening %s: %s\n", logPath, err.Error())
			os.Exit(1)
		}

		dynamicSyncer = &DynamicFileSyncer{
			currentWritter: logFile,
		}
	})
	return dynamicSyncer
}

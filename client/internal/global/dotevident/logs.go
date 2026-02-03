package dotevident

import (
	"fmt"
	"path/filepath"
	"time"
)

const (
	_LOGS_DIR = "logs"
)

type logs interface {
	GetLogFilePath(cmd string) (logFilePath string)
}

type logsImpl struct {
	logsPath string
}

func newLogs(dotEvidentPath string) logs {
	l := &logsImpl{
		logsPath: filepath.Join(dotEvidentPath, _LOGS_DIR),
	}
	err := healthCheck(l.logsPath)
	if err != nil {
		panic(err)
	}

	return l
}

func (self *logsImpl) GetLogFilePath(cmd string) string {
	now := time.Now()
	return filepath.Join(self.logsPath,
		fmt.Sprintf("%s-%d%d%d_%d%d%d.log",
			cmd,
			now.Year(), now.Month(), now.Day(),
			now.Hour(), now.Minute(), now.Second(),
		))
}

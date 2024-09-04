package internal

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
)

var client *logrus.Logger

var (
	callerInitOnce     sync.Once
	commonPackage      string
	minimumCallerDepth int
	maximumCallerDepth = 10
)

func getPackageName(funcName string) string {
	lastSlash := strings.LastIndex(funcName, "/")
	if lastSlash == -1 {
		return ""
	}
	secondLastSlash := strings.LastIndex(funcName[:lastSlash], "/")
	if secondLastSlash == -1 {
		return funcName[:lastSlash]
	}
	return funcName[secondLastSlash+1 : lastSlash]
}

func getCaller() *runtime.Frame {
	callerInitOnce.Do(
		func() {
			pcs := make([]uintptr, maximumCallerDepth)
			_ = runtime.Callers(0, pcs)

			for i := 0; i < maximumCallerDepth; i++ {
				funcName := runtime.FuncForPC(pcs[i]).Name()
				if strings.Contains(funcName, "GetCaller") {
					commonPackage = getPackageName(funcName)
					break
				}
			}

			minimumCallerDepth = 3
		},
	)

	pcs := make([]uintptr, maximumCallerDepth)
	depth := runtime.Callers(minimumCallerDepth, pcs)
	frames := runtime.CallersFrames(pcs[:depth])

	commonPackageFound := false
	for f, again := frames.Next(); again; f, again = frames.Next() {
		pkg := getPackageName(f.Function)

		if strings.Contains(pkg, commonPackage) {
			commonPackageFound = true
		}
		if !strings.Contains(pkg, commonPackage) && commonPackageFound {
			return &f
		}
	}

	return nil
}

func NewLoggerClient(
	level logrus.Level,
) {
	client = &logrus.Logger{
		Out:   os.Stderr,
		Hooks: make(logrus.LevelHooks),
		Level: level,
		Formatter: &logrus.JSONFormatter{
			FieldMap: logrus.FieldMap{
				logrus.FieldKeyTime:  "@timestamp",
				logrus.FieldKeyLevel: "level",
				logrus.FieldKeyMsg:   "message",
				logrus.FieldKeyFunc:  "function_name", // non-ECS
			},
			CallerPrettyfier: func(*runtime.Frame) (function string, file string) {
				frame := getCaller()
				if frame == nil {
					return
				}
				pc := frame.Entry
				file = frame.File
				line := frame.Line

				funcInfo := runtime.FuncForPC(pc)
				if funcInfo == nil {
					return
				}
				filename := fmt.Sprintf("%s:%d", file, line)

				return funcInfo.Name(), filename
			},
		},
	}

	client.SetReportCaller(true)
}

func Logger() *logrus.Logger {
	return client
}

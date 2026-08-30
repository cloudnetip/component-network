package logger

import (
	"log"
	"os"
)

var debug = os.Getenv("LOG_DEBUG") == "true"

func IsDebugMode() bool {
	return debug
}

func Debug(a ...any) {
	if !debug {
		return
	}
	if len(a) > 0 {
		if s, ok := a[0].(string); ok {
			a[0] = "[debug]" + s
		}
	}
	log.Println(a...)
}

func Debugf(s string, a ...any) {
	if !debug {
		return
	}
	log.Printf("[debug]"+s, a...)
}

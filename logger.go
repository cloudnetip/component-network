package main

import (
	"log"
	"os"
)

var logger = &Logger{
	debug: os.Getenv("LOG_DEBUG") == "true",
}

type Logger struct {
	debug bool
}

func (l *Logger) Debug(a ...any) {
	if !l.debug {
		return
	}
	if _, ok := a[0].(string); ok {
		a[0] = "[debug]" + a[0].(string)
	}
	log.Println(a...)
}

func (l *Logger) Debugf(s string, a ...any) {
	if !l.debug {
		return
	}
	log.Printf("[debug]"+s, a...)
}

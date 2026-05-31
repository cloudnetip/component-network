package collector

import (
	"fmt"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"log"
	"net/http"
	"net/http/pprof"
	"os"
	"runtime"
)

func Pprof() {
	hostname, err := os.Hostname()
	if err != nil {
		log.Println("[pprof] get hostname err:", err)
	}
	if os.Getenv("PPROF") != "true" && os.Getenv("PPROF") != hostname {
		return
	}

	runtime.SetBlockProfileRate(1)
	runtime.SetMutexProfileFraction(1)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, "Stats metrics!")
	})

	// prometheus
	mux.Handle("/metrics", promhttp.Handler())

	// pprof handlers
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	// pprof profiles
	mux.Handle("/debug/pprof/allocs", pprof.Handler("allocs"))
	mux.Handle("/debug/pprof/block", pprof.Handler("block"))
	mux.Handle("/debug/pprof/goroutine", pprof.Handler("goroutine"))
	mux.Handle("/debug/pprof/heap", pprof.Handler("heap"))
	mux.Handle("/debug/pprof/mutex", pprof.Handler("mutex"))
	mux.Handle("/debug/pprof/threadcreate", pprof.Handler("threadcreate"))

	log.Println("[pprof] enabled, check port 6060")
	err = http.ListenAndServe(":6060", mux)
	log.Println("[pprof] listen err:", err)
}

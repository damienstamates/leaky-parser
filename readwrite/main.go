package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"runtime"
	"runtime/debug"

	// "mime/multipart"
	"net/http"
	"net/http/pprof"
	"os"

	//"runtime/debug"
	"time"

	"github.com/julienschmidt/httprouter"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	timeFormat = "2006-01-02 15:04:05"
	file       = "1000.csv"
)

func pprofIndex(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	pprof.Index(w, r)
}

func pprofCmdline(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	pprof.Cmdline(w, r)
}

func pprofProfile(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	pprof.Profile(w, r)
}

func pprofSymbol(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	pprof.Symbol(w, r)
}

func pprofTrace(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	pprof.Trace(w, r)
}

func main() {
	r := httprouter.New()

	r.GET("/leaky/debug/pprof/", pprofIndex)
	r.GET("/leaky/debug/pprof/cmdline", pprofCmdline)
	r.GET("/leaky/debug/pprof/profile", pprofProfile)
	r.GET("/leaky/debug/pprof/symbol", pprofSymbol)
	r.GET("/leaky/debug/pprof/trace", pprofTrace)

	r.Handler("GET", "/leaky/metrics", promhttp.Handler())
	r.Handler("GET", "/leaky/debug/pprof/allocs", pprof.Handler("allocs"))
	r.Handler("GET", "/leaky/debug/pprof/block", pprof.Handler("block"))
	r.Handler("GET", "/leaky/debug/pprof/goroutine", pprof.Handler("goroutine"))
	r.Handler("GET", "/leaky/debug/pprof/heap", pprof.Handler("heap"))
	r.Handler("GET", "/leaky/debug/pprof/mutex", pprof.Handler("mutex"))
	r.Handler("GET", "/leaky/debug/pprof/threadcreate", pprof.Handler("threadcreate"))

	go func() {
		log.Fatal(http.ListenAndServe(":9900", r))
	}()

	inputFile, err := os.OpenFile("/Users/sta8071/go/src/github.com/damienstamates/leaky-parser/"+file,
		os.O_RDONLY, 0666)
	if err != nil {
		log.Fatalf("error opening fifty million file: %v", err)
	}
	// os.O_SYNC works best. Remove 0x4000 (syscall.O_DIRECT)
	outputFile, err := os.OpenFile("/Users/sta8071/go/src/github.com/damienstamates/leaky-parser/test/output.csv",
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error creating output file: %v", err)
	}

	var (
		row   []byte
		count int
		stats runtime.MemStats

		endInput   = make(chan struct{})
		begin      = time.Now()
		rbuf, wbuf = io.Pipe()
		reader     = bufio.NewReaderSize(rbuf, 1<<12)
	)

	inf, _ := inputFile.Stat()
	bufferSize := inf.Size() / (1 << 6)
	// bufferSize = 2 << 20

	log.Printf("File Size [%v]\n", inf.Size())

	go readFileToPipe(bufferSize, inputFile, wbuf, rbuf, endInput)

	// Let the worker get a head start.
	for i := 0; i < 1000; i++ {
		time.Sleep(1 * time.Millisecond)
	}

	for {
		row, err = reader.ReadBytes('\n')
		if err == io.ErrClosedPipe {
			if len(row) != 0 {
				// Write the last row in the file and append new line delimiter.
				row = append(row, '\n')
				i := bytes.IndexByte(row, '\u0000')
				outputFile.Write(row[:i+1])
			}
			if len(row) == 0 {

				break
			}
			// Break out of the forever loop.
		} else if err != nil {
			log.Fatalf("error reading input file: %v", err)
		}

		outputFile.Write(row)

		count++

		if count%100 == 0 {
			runtime.ReadMemStats(&stats)
			fmt.Printf("[%v] +++--> BEFORE Flushing Writer Sync Rows read [% 10d] [% 3v Mib]\n", time.Now().Format(timeFormat), count, stats.Alloc/1024/1024)
			outputFile.Sync()
		}
	}

	log.Printf("Syncing and closing files in [%v]\n", time.Since(begin))

	// Sync and Close output file.
	outputFile.Sync()
	outputFile.Close()

	row = nil

	log.Printf("Finished writing file in [%v] now cleaning up\n", time.Since(begin))

	cleanup()

	log.Printf("Finished cleaning up after [%v]\n", time.Since(begin))
}

func readFileToPipe(bufSize int64, inputFile *os.File, pipeWriter *io.PipeWriter,
	pipeReader *io.PipeReader, endInput chan struct{}) {

	var chunk = make([]byte, bufSize)
	var err error
	var n int

	for {
		n, err = inputFile.Read(chunk)
		if err == io.EOF {
			log.Printf("End of Input in worker.\n")
			pipeReader.Close()
			endInput <- struct{}{}
			break
		} else if err != nil {
			pipeReader.CloseWithError(err)
			break
		}

		pipeWriter.Write(chunk[:n])
	}

	// Clean up and close pipe.
	pipeWriter.Close()
	inputFile.Close()
	chunk = nil
}

func cleanup() {
	for i := 0; i < 5; i++ {
		debug.FreeOSMemory()
	}
}

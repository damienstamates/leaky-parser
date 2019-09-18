package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/pprof"
	_ "net/http/pprof"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	buffer "github.com/ShoshinNikita/go-disk-buffer"
	"github.com/julienschmidt/httprouter"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// Default paths and filename
	filePath      = ""
	fileWorkers   = ""
	fileSource    = ""
	fileEncrypted = fileSource + "E.csv"
	fileRow       = fileSource + ".row"
	fileDecrypted = fileSource + "D.csv"

	// Encryption Vars
	encryptedDelimiter  = "###~~###"
	originalDelimiter   = "\n"
	decryptionDelimiter = "\n"
	// encryptionKey       = "0123456789"
	encryptionKey = [32]byte{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'}

	// App Workers
	numberOfWorkers = 100000

	// Buffered Chans
	// numberReadChans    = 10000
	// numberWriteChans   = 10000
	numberReadChans    = 10
	numberWriteChans   = 10
	syncWriteAfterRows = 100000

	timeFormat = "2006-01-02 15:04:05"

	memAllocMax = buffer.DefaultMaxMemorySize
)

const (
	// KeySize is the size of a NaCl secret key.
	KeySize = 32

	// NonceSize is the size of a NaCl nonce.
	NonceSize = 24

	// NaclLen is the length of a NaCl secret key.
	NaclLen = 32

	// HashLen is the length of a hash.
	HashLen = 44
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

	filePath = os.Getenv("LEAKY_PATH")
	if filePath == "" {
		fmt.Printf("env var LEAKY_PATH not found env value [%s] \n", filePath)
		os.Exit(1)
	}
	fileSource = os.Getenv("LEAKY_FILE")
	if fileSource == "" {
		fmt.Printf("env var LEAKY_FILE not found env value [%s] \n", fileSource)
		os.Exit(1)
	}
	fileWorkers = os.Getenv("LEAKY_WORKERS")
	if fileWorkers != "" {
		numberOfWorkers, _ = strconv.Atoi(fileWorkers)
	}
	fileEncrypted = fileSource + ".E.csv"
	fileDecrypted = fileSource + ".D.csv"
	fileRow = fileSource + ".row"

	begin := time.Now()
	fmt.Println("Check memory before start .......")
	leakyFunction()
	fmt.Println("End of process Check memory .......")

	fmt.Printf("Time elapsed [%v]\n", time.Since(begin))
	time.Sleep(5 * time.Minute)

}

func leakyFunction() {
	// ENCRYPT
	fileSourcePTR, err := os.Open(filePath + "/" + fileSource)
	if err != nil {
		fmt.Printf("error reading Input file [%s]", err)
		os.Exit(1)
	}

	// orig := buffer.NewBufferWithMaxMemorySize(memAllocMax)
	// orig.ReadFrom(fileSourcePTR)

	// encrypted := buffer.NewBufferWithMaxMemorySize(memAllocMax)
	encrypted, err := os.OpenFile(filePath+"/"+fileEncrypted, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		fmt.Printf("error reading output file [%s]", err)
		os.Exit(1)
	}

	rowFile, err := os.OpenFile(filePath+"/"+fileRow, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		fmt.Printf("error reading output file [%s]", err)
		os.Exit(1)
	}

	encryptReader(fileSourcePTR, encrypted, rowFile)

	encrypted.Close()
	rowFile.Close()

	fileSourcePTR.Close()

	fileSourcePTR, _ = os.Open(filePath + "/" + fileSource)

	encrypted, err = os.OpenFile(filePath+"/"+fileEncrypted, os.O_RDWR, 0666)
	if err != nil {
		fmt.Printf("error reading output file [%s]", err)
		os.Exit(1)
	}

	rowFile, err = os.OpenFile(filePath+"/"+fileRow, os.O_RDWR, 0666)
	if err != nil {
		fmt.Printf("error reading output file [%s]", err)
		os.Exit(1)
	}

	fileDecryptedPTR, err := os.OpenFile(filePath+"/"+fileDecrypted, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		fmt.Printf("error reading output file [%s]", err)
		os.Exit(1)
	}

	defer rowFile.Close()
	defer encrypted.Close()
	defer fileDecryptedPTR.Close()

	decryptReader(encrypted, fileDecryptedPTR, rowFile, fileSourcePTR)

	// encrypted.Reset()
}

func encryptReader(fi io.Reader, fo *os.File, rowFile *os.File) {
	var (
		writerWG sync.WaitGroup
		// rowWG    sync.WaitGroup
		stats runtime.MemStats
	)

	readCh := make(chan []byte, numberReadChans)
	// rowCh := make(chan []byte, numberWriteChans)
	doneReadCh := make(chan bool)
	writeCh := make(chan rowInfo, numberWriteChans)
	// writeCh := make(chan WriterToResetter, numberWriteChans)

	fileScanner := bufio.NewReader(fi)
	// fileScanner := bufio.NewScanner(fi)
	// fileScanner.Split(onDelimiter(originalDelimiter))

	writerWG.Add(1)
	// rowWG.Add(1)
	// // go writer(writeCh, fo, &writerWG)
	// go writer(writeCh, fo, &writerWG)
	go writer(writeCh, fo, rowFile, &writerWG)

	var m sync.Mutex
	for i := 0; i < numberOfWorkers; i++ {
		go encryptionWorker(readCh, writeCh, doneReadCh, fo, rowFile, &m)
	}

	var header sync.Once
	oncebody := func() {
		tmp, _ := fileScanner.ReadBytes('\n')
		row := []byte(tmp)

		n, err := EncryptNACL(encryptionKey, row, &row)
		if err != nil {
			log.Fatalf("error encrypting data: %v", err)
		}
		// rowLen := strconv.Itoa(len) + "\n"
		rowLen := strconv.Itoa(n) + "\n"

		writeCh <- rowInfo{data: row, rowLen: rowLen}
	}

	j := 0
	var row []byte
	var err error

	for {
		header.Do(oncebody)
		row, err = fileScanner.ReadBytes('\n')
		// row, _, err := fileScanner.ReadLine()
		if err == io.EOF || len(row) == 0 {
			break
		} else if err != nil && len(row) == 0 {
			log.Fatalf("error reading original file: %v", err)
		}

		// log.Printf("ENCRYPTION: ROWLENGTH[%d]\n", len(row))

		j++

		readCh <- row
	}

	runtime.ReadMemStats(&stats)
	fmt.Printf("[%v] --> Encrypt Rows read [% 10d] [% 3v Mib]\n", time.Now().Format(timeFormat), j, stats.Alloc/1024/1024)
	close(readCh)

	for i := 0; i < numberOfWorkers; i++ {
		<-doneReadCh
	}

	close(writeCh)
	close(doneReadCh)

	// rowWG.Wait()
	writerWG.Wait()

	fo.Sync()
	rowFile.Sync()

	fmt.Printf("Encrypt Length Write Chan [%d], Read Chan [%d]\n", len(writeCh), len(readCh))
	// fmt.Printf("FILE IS %d BYTES\n", charCount)
}

type EmptyWriter struct{}

func (*EmptyWriter) Write([]byte) (int, error) { return 0, nil }

func decryptReader(fi io.Reader, fo *os.File, rowFile *os.File, orig *os.File) {
	var (
		stats    runtime.MemStats
		writerWG sync.WaitGroup
		// breaker  bool
	)

	readCh := make(chan rowInfo, numberReadChans)
	doneReadCh := make(chan bool)
	writeCh := make(chan rowInfo, numberWriteChans)

	// fileScanner := bufio.NewReader(fi)
	origScanner := bufio.NewReader(orig)
	origScanner.ReadString('\n')
	rowScanner := bufio.NewReader(rowFile)

	writerWG.Add(1)
	go writer(writeCh, fo, &EmptyWriter{}, &writerWG)

	var m sync.Mutex
	for i := 0; i < numberOfWorkers; i++ {
		go decryptionWorker(readCh, writeCh, fo, doneReadCh, &m)
	}

	var header sync.Once
	oncebody := func() {
		tmp, _ := rowScanner.ReadString('\n')
		rowParsed, _ := strconv.Atoi(tmp[:len(tmp)-1])

		var row = make([]byte, rowParsed)
		// fileScanner.Read(row[:])
		io.ReadAtLeast(fi, row[:], rowParsed)
		tmpRow, _ := DecryptNACL(encryptionKey, row)

		fmt.Printf("Header Length [%d]\n", len(row))

		writeCh <- rowInfo{data: tmpRow, rowLen: ""}
	}

	j := 0
	for {
		header.Do(oncebody)

		rowLen, err := rowScanner.ReadString('\n')
		if err == io.EOF && len(rowLen) == 0 {
			break
		} else if err != nil && len(rowLen) == 0 {
			log.Fatalf("error reading rowFile: %v", err)
		}
		rowParsed, err := strconv.Atoi(rowLen[:len(rowLen)-1])
		if err != nil {
			log.Fatalf("error parsing row length: %v", err)
		}

		// log.Printf("PARSED ROW LENGTH [%d]\n", rowParsed)
		var row = make([]byte, rowParsed)

		// n, err := fileScanner.Read(row[:])
		// io.ReadFull(fi, row[:])
		io.ReadAtLeast(fi, row[:], rowParsed)
		if err == io.EOF && len(rowLen) == 0 {
			break
		} else if err != nil && len(rowLen) == 0 {
			log.Fatalf("error reading encrypted file: %v", err)
		}

		origRow, err := origScanner.ReadString('\n')
		if err != nil && err != io.EOF {
			log.Fatalf("error while reading original file: %v", err)
		}

		// log.Printf("SHOULDBE[%d] GOT[%d]\n",
		// 	len(origRow)+24+poly1305.TagSize+1, n)

		// if n != len(origRow)+24+poly1305.TagSize {
		// 	log.Fatalf("%d doesn't equal %d\n", n, len(origRow)+24+poly1305.TagSize)
		// }

		j++

		readCh <- rowInfo{data: row, origRow: []byte(origRow)}
	}

	runtime.ReadMemStats(&stats)
	fmt.Printf("[%v] --> Decrypt Rows read [% 10d] [% 3v Mib]\n", time.Now().Format(timeFormat), j, stats.Alloc/1024/1024)

	close(readCh)

	for i := 0; i < numberOfWorkers; i++ {
		<-doneReadCh
	}

	close(writeCh)
	close(doneReadCh)
	writerWG.Wait()

	fo.Sync()
	rowFile.Sync()

	fmt.Printf("Decrypt Length Write Chan [%d], Read Chan [%d]\n", len(writeCh), len(readCh))
}

// var (
// 	charCount uint64
// )

type WriterToResetter interface {
	io.WriterTo
	Reset()
}

func encryptionWorker(read chan []byte, writeCh chan rowInfo, doneRead chan bool, out io.Writer, rowFile io.Writer, m *sync.Mutex) {
	// func encryptionWorker(read chan []byte, writeCh chan WriterToResetter, doneRead chan bool, fo io.ReadWriter, m *sync.Mutex) {
	for row := range read {
		// b := readPool.Get().(*bytes.Buffer)
		if row[len(row)-1] != '\n' {
			row = append(row, '\n')
			// log.Printf("OLD[%d] NEW[%d]\n", old, len(row))
		}
		// old := len(row)

		n, err := EncryptNACL(encryptionKey, row, &row)
		if err != nil {
			log.Fatalf("error encrypting data: %v", err)
		}
		rowLen := strconv.Itoa(n) + "\n"
		// rowLen := strconv.Itoa(length) + "\n"

		// log.Printf("LEN_ORIG[%d] LEN_ENC[%d]\n", old, len(row))

		// atomic.AddUint64(&charCount, uint64(len(tmp)))

		// fmt.Printf("len[%d] data[%s] hex[%x]\n", len(row), row, row)
		// rowLen := strconv.Itoa(len(row)) + "\n"

		// rowLen := strconv.Itoa(len(tmp)) + "\n"
		// _ = EncryptNACL(&encryptionKey, row, b)

		// b.WriteString(encryptedDelimiter)

		// writeCh <- rowInfo{data: row, rowLen: strconv.Itoa(len(row)) + "\n"}
		writeCh <- rowInfo{data: row, rowLen: rowLen}

		// m.Lock()
		// // out.Write(row)
		// // rowFile.Write([]byte(rowLen))
		// out.Write(row)
		// rowFile.Write([]byte(rowLen))
		// m.Unlock()
	}
	doneRead <- true
}

// func decryptionWorker(read chan []byte, writerCh chan []byte, out *os.File, doneReadCh chan bool) {
func decryptionWorker(read chan rowInfo, writerCh chan rowInfo, orig io.Reader, doneRead chan bool, m *sync.Mutex) {
	for row := range read {
		tmp, err := DecryptNACL(encryptionKey, row.data)
		// log.Printf("ORIGLEN[%d] ENC_SHOULDBE[%d] ENCLEN[%d] DECLEN[%d] {\n\t\"original\": \"%s\"\n\t\"decrypted\": \"%s\"\n}\n",
		// 	len(row.origRow), len(row.origRow)+24+poly1305.TagSize, len(row.data), len(tmp), row.origRow, tmp)
		if err != nil {
			log.Fatalf("error decrypting data: %v", err)
		}
		if tmp[len(tmp)-1] != '\n' {
			tmp = append(tmp, '\n')
		}

		// row = append(row, '\n')
		// b.WriteString(decryptionDelimiter)
		// if b.Len() == 1 {
		// 	fmt.Println("WRONG -", string(row))
		// }

		// m.Lock()
		// fo.Write(tmp)
		// m.Unlock()
		// m.Lock()
		// b.WriteTo(fo)
		// m.Unlock()

		// b.Reset()
		// readPool.Put(b)

		// runtime.GC()
		writerCh <- rowInfo{data: tmp, rowLen: ""}
	}
	doneRead <- true
}

type rowInfo struct {
	data    []byte
	rowLen  string
	origRow []byte
}

// func writer(writerCh chan WriterToResetter, out io.Writer, writerWG *sync.WaitGroup) {
func writer(writerCh chan rowInfo, fo io.Writer, rowFile io.Writer, writerWG *sync.WaitGroup) {
	var (
		// row   []byte
		stats runtime.MemStats
	)

	// w := bufio.NewWriter(out)

	j := 0
	for b := range writerCh {
		// b.WriteTo(out)
		// b.Reset()
		fo.Write(b.data)
		rowFile.Write([]byte(b.rowLen))
		// readPool.Put(b)

		// out.Write(row)
		// w.Write(row)
		j++
		// every 1000000 rows empty cache
		if (j % syncWriteAfterRows) == 0 {
			runtime.ReadMemStats(&stats)
			fmt.Printf("[%v] +++--> BEFORE Flushing Writer Sync Rows read [% 10d] [% 3v Mib]\n", time.Now().Format(timeFormat), j, stats.Alloc/1024/1024)
			// runtime.GC()
			debug.FreeOSMemory()
			// w.Flush()
		}
	}
	// w.Flush()
	runtime.ReadMemStats(&stats)
	fmt.Printf("[%v] +++--> END Writer Sync Rows read [% 10d] [% 3v Mib]\n", time.Now().Format(timeFormat), j, stats.Alloc/1024/1024)
	writerWG.Done()
}

// onDelimiter is a custom SplitFunc for bufio.Split to split on semicolon and concatenate multiple lines
func onDelimiter(delim string) bufio.SplitFunc {
	customSplit := func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		if atEOF && len(data) == 0 {
			return 0, nil, nil
		}
		// returns index of first instance of delimiter. So I need to advance
		if i := strings.Index(string(data), delim); i >= 0 {
			return i + len(delim), data[0:i], nil
		}
		if atEOF {
			return len(data), data, nil
		}
		return
	}
	return customSplit
}

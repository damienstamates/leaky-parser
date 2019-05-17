package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/damienstamates/sweeper"
)

var (
	// Default paths and filename
	filePath      = ""
	fileWorkers   = ""
	fileSource    = ""
	fileEncrypted = fileSource + "E.csv"
	fileDecrypted = fileSource + "D.csv"

	// Encryption Vars
	encryptedDelimiter  = "###~~###"
	originalDelimiter   = "\n"
	decryptionDelimiter = "\n"
	encryptionKey       = "0123456789"

	// App Workers
	numberOfWorkers = 100000

	// Buffered Chans
	numberReadChans    = 10000
	numberWriteChans   = 10000
	syncWriteAfterRows = 100000

	timeFormat = "2006-01-02 15:04:05"
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

func main() {
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

	fmt.Println("Check memory before start .......")
	leakyFunction()
	fmt.Println("End of process Check memory .......")
	time.Sleep(5 * time.Minute)

}

func leakyFunction() {
	// ENCRYPT
	fileSourcePTR, err := os.Open(filePath + "/" + fileSource)
	if err != nil {
		fmt.Printf("error reading Input file [%s]", err)
		os.Exit(1)
	}
	defer fileSourcePTR.Close()

	fileEncryptedPTR, err := os.Create(filePath + "/" + fileEncrypted)
	if err != nil {
		fmt.Printf("error reading output file [%s]", err)
		os.Exit(1)
	}

	encryptReader(fileSourcePTR, fileEncryptedPTR)
	fileEncryptedPTR.Close()

	// DECRYPT
	fileEncryptedPTR, err = os.Open(filePath + "/" + fileEncrypted)
	if err != nil {
		fmt.Printf("error reading Input file [%s]", err)
		os.Exit(1)
	}

	fileDecryptedPTR, err := os.Create(filePath + "/" + fileDecrypted)
	if err != nil {
		fmt.Printf("error reading output file [%s]", err)
		os.Exit(1)
	}

	decryptReader(fileEncryptedPTR, fileDecryptedPTR)
	fileEncryptedPTR.Close()
	fileDecryptedPTR.Close()
}

func encryptReader(fi *os.File, fo *os.File) {
	var (
		writerWG sync.WaitGroup
		stats    runtime.MemStats
	)

	readCh := make(chan []byte, numberReadChans)
	doneReadCh := make(chan bool)
	writeCh := make(chan []byte, numberWriteChans)

	fileScanner := bufio.NewScanner(fi)
	fileScanner.Split(onDelimiter(originalDelimiter))

	writerWG.Add(1)
	go writer(writeCh, fo, &writerWG)

	for i := 0; i < numberOfWorkers; i++ {
		go encryptionWorker(readCh, writeCh, doneReadCh)
	}

	j := 0
	for fileScanner.Scan() {
		readCh <- []byte(fileScanner.Text())
		j++
		if (j % syncWriteAfterRows) == 0 {
			runtime.ReadMemStats(&stats)
			fmt.Printf("[%v] --> Encrypt Rows read [% 10d] [% 3v Mib]\n", time.Now().Format(timeFormat), j, stats.Alloc/1024/1024)
			fo.Sync()
		}
	}

	fo.Sync()
	runtime.ReadMemStats(&stats)
	fmt.Printf("[%v] --> Encrypt Rows read [% 10d] [% 3v Mib]\n", time.Now().Format(timeFormat), j, stats.Alloc/1024/1024)
	close(readCh)

	for i := 0; i < numberOfWorkers; i++ {
		<-doneReadCh
	}

	close(writeCh)
	close(doneReadCh)
	writerWG.Wait()

	fmt.Printf("Encrypt Length Write Chan [%d], Read Chan [%d]\n", len(writeCh), len(readCh))
}

func decryptReader(fi *os.File, fo *os.File) {
	var (
		stats    runtime.MemStats
		writerWG sync.WaitGroup
		breaker  bool
	)

	readCh := make(chan []byte, numberReadChans)
	doneReadCh := make(chan bool)
	writeCh := make(chan []byte, numberWriteChans)

	fileScanner := sweeper.NewSweeper(fi)

	writerWG.Add(1)
	go writer(writeCh, fo, &writerWG)

	for i := 0; i < numberOfWorkers; i++ {
		go decryptionWorker(readCh, writeCh, doneReadCh)
	}

	j := 0
	for {
		row, err := fileScanner.ReadSliceWithString(encryptedDelimiter)
		if err != nil {
			if err == io.EOF {
				err = nil
				breaker = true
			} else {
				fmt.Printf("ERROR WHEN READING ROW: %v\n", err)
				fmt.Printf("row%v", row)
			}
		}

		if breaker {
			break
		}

		newRow := row[:len(row)-len(encryptedDelimiter)]
		readCh <- newRow
		j++
		if (j % syncWriteAfterRows) == 0 {
			runtime.ReadMemStats(&stats)
			fmt.Printf("[%v] --> Decrypt Rows read [% 10d] [% 3v Mib]\n", time.Now().Format(timeFormat), j, stats.Alloc/1024/1024)
			fo.Sync()
		}
	}

	fo.Sync()
	runtime.ReadMemStats(&stats)
	fmt.Printf("[%v] --> Decrypt Rows read [% 10d] [% 3v Mib]\n", time.Now().Format(timeFormat), j, stats.Alloc/1024/1024)

	close(readCh)

	for i := 0; i < numberOfWorkers; i++ {
		<-doneReadCh
	}

	close(writeCh)
	close(doneReadCh)
	writerWG.Wait()

	fmt.Printf("Decrypt Length Write Chan [%d], Read Chan [%d]\n", len(writeCh), len(readCh))
}

// func encryptionWorker(read chan []byte, writerCh chan []byte, out *os.File, doneReadCh chan bool) {
func encryptionWorker(read, writer chan []byte, doneRead chan bool) {
	var row []byte

	for row = range read {
		row, _ = EncryptNACL(&encryptionKey, row)
		row = append(row, []byte(encryptedDelimiter)...)
		writer <- row
	}
	doneRead <- true
}

// func decryptionWorker(read chan []byte, writerCh chan []byte, out *os.File, doneReadCh chan bool) {
func decryptionWorker(read, writer chan []byte, doneRead chan bool) {
	var row []byte

	for row = range read {
		row, _ = DecryptNACL(&encryptionKey, row)
		row = append(row, []byte(decryptionDelimiter)...)
		if len(row) == 1 {
			fmt.Println("WRONG -", string(row))
		}
		writer <- row
	}
	doneRead <- true
}

func writer(writerCh chan []byte, out *os.File, writerWG *sync.WaitGroup) {
	var (
		row   []byte
		stats runtime.MemStats
	)

	w := bufio.NewWriter(out)

	j := 0
	for row = range writerCh {
		w.Write(row)
		j++
		// every 1000000 rows empty cache
		if (j % syncWriteAfterRows) == 0 {
			runtime.ReadMemStats(&stats)
			fmt.Printf("[%v] +++--> BEFORE Flushing Writer Sync Rows read [% 10d] [% 3v Mib]\n", time.Now().Format(timeFormat), j, stats.Alloc/1024/1024)
			w.Flush()
		}
	}
	w.Flush()
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

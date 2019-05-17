# Leaky Parser

## Application Objective

This app will read a csv file, encrypts, decrypts, and outputs a csv file. The intent of this app is to demonstrate a potential memory issue as it processes a file using a fan out/fan in method worker channels. The outcome of the execution results in memory usage that is slowly released but only a fraction over a period of time and an inconsistent memory pattern within a containerized image vs local execution.

Included in this repository are two sample csv files that can be used to run the application. To see the memory issue on a larger scale, an even bigger file with more records will be needed. For the sake of keeping this repository small, copying the contents of the one million record csv unto itself can do the job.

## Application Logic

Phase 1: Encryption

- Opens a file (preferably csv) specified by the environment variables
- Reads the file line by line into a encryption channel
- The encryption workers in the channel performs a simple encryption
- Send the encrypted line to a writer channel
- The writer will write the encrypted string with special delimiter to a new file

Phase 2: Decryption

- Opens the encrypted file from Phase 1
- Reads the file into a decryption channel by splitting on the special delimiter
- The encrypted string gets decrypted and sent to the writer channel
- The writer will write the decrypted string to a new file

In the end there will be two new files generated along with the original file, the encrypted and decrypted file.

## Building the app

``` shell
go build ./...
```

## Setup before running

This app requires three environment variables.

``` shell
export LEAKY_WORKERS="1000"
export LEAKY_FILE="<file name"
export LEAKY_PATH="<path to the file>"
```

## Running the app

``` shell
./leaky-parser
```

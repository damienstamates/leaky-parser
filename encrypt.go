package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"log"

	buffer "github.com/ShoshinNikita/go-disk-buffer"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/nacl/secretbox"
)

// GenerateNACLKey creates a new random secret key.
//
// NaCL (pronounced "salt") stands for Networking and Cryptography Library.
// Since we are using secretbox, which uses XSalsa20 and Poly1305 to encrypt and
// authenticate messages with secret-key cryptography, a secret encryption key
// is necessary.
// Think of secretbox as a safe, and the combination to the safe would be the
// NaCl encryption key, which must be kept secret.
//
// rand.Reader is a global, shared instance of a cryptographically
// secure pseudo-random number generator. For example, on other Unix-like systems,
// Reader reads from /dev/urandom, which is a special file that serve as a
// cryptographically-secure random number generator (CSRNG).
func GenerateNACLKey() (string, error) {
	// new allocates memory of KeySize to a byte slice, and returns a pointer.
	key := new([KeySize]byte)
	// io.ReadFull reads length of key from rand.Reader into key.
	_, err := io.ReadFull(rand.Reader, key[:])
	if err != nil {
		return "", err
	}

	return string(key[:]), err
}

// GenerateNACLNonce creates a new random nonce.
//
// In cryptography, nonce (number used only once) is an arbitrary number that *MUST*
// only be used once. but it is not considered secret and can be transmitted or
// stored alongside the ciphertext. A good source of nonces are just sequences
// of 24 random bytes.
//
// rand.Reader is a global, shared instance of a cryptographically
// secure pseudo-random number generator. For example, on other Unix-like systems,
// Reader reads from /dev/urandom, which is a special file that serve as a
// cryptographically-secure random number generator (CSRNG).
func GenerateNACLNonce() (*[NonceSize]byte, error) {
	// new allocates memory of NonceSize to a byte slice, and returns a pointer.
	nonce := new([NonceSize]byte)
	// io.ReadFull reads exact length of nonce from rand.Reader into nonce.
	_, err := io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		return nil, err
	}

	return nonce, err
}

var (
	// ErrEncrypt is returned when encryption fails.
	ErrEncrypt = errors.New("secret: encryption failed")

	// ErrDecrypt is returned when decryption fails.
	ErrDecrypt = errors.New("secret: decryption failed")

	// secretbox encrypts and authenticates messages with secret-key cryptography.
	// Think of secretbox as a safe, and the combination to the safe would be the
	// NaCl encryption key, which must be kept secret.
	// Open authenticates and decrypts encrypted messages.
)

// EncryptNACL encrypt using NaCL (Networking and Cryptography library)
//
// A nonce must not be reused with the same secret key to prevent replay attacks.
// In other words, the secret key and nonce pair must be unique for each distinct message.
func EncryptNACL(key *string, message []byte, b *buffer.Buffer) error {
	// genNACLNonce generates a new random nonce (number used only once).
	nonce, err := GenerateNACLNonce()
	// if err exists, return encrypt error
	if err != nil {
		return ErrEncrypt
	}
	newKey := new([KeySize]byte)
	copy(newKey[:], *key)

	out := make([]byte, len(nonce))
	copy(out, nonce[:])

	// Seal appends an encrypted and authenticated copy of message to out, using a
	// secret encryption key and a nonce.
	b.Write(secretbox.Seal(out, message, nonce, newKey))
	// newout := secretbox.Seal(out, message, nonce, newKey)
	return nil
}

// DecryptNACL will decrypt NACL encrypted message
//
// A nonce must not be reused with the same secret key to prevent replay attacks.
// In other words, the secret key and nonce pair must be unique for each distinct message.
func DecryptNACL(key *string, message []byte, b *buffer.Buffer) error {
	// if length of message is less than size of nonce plus the number of bytes
	// of overhead when boxing a message, return decrypt error.
	if len(message) < (NonceSize + secretbox.Overhead) {
		return ErrDecrypt
	}
	//log.Printf("in DecryptNACL using KEY [%x]\n", *key)
	newKey := new([KeySize]byte)
	copy(newKey[:], *key)

	nonce := new([NonceSize]byte)
	copy(nonce[:], message[:NonceSize])
	// Open decrypts and authenticates an encrypted message (or ciphertext) using a
	// secret encryption key and a nonce.
	out, ok := secretbox.Open(nil, message[NonceSize:], nonce, newKey)
	// if not ok, return decrypt error
	if !ok {
		return ErrDecrypt
	}

	b.Write(out)

	return nil

	//log.Printf("DECRYPTION IS DONE [%s] \n ", newout)
	// return out, nil
}

// GenerateRandomStatic will generate a random secret encryption key and static hash.
// The static.static table contains a static_key and static_hash column.
func GenerateRandomStatic() (*string, *string) {
	key, _ := GenerateNACLKey()
	hash, _ := GenerateRandomHash(32)
	return &key, &hash
}

// HashSalted will hash and salt a given text
//
// GenerateFromPassword returns a bcrypt hash of byte slice
// of the password at DefaultCost of 10.
func HashSalted(text []byte) ([]byte, error) {
	hash, _ := bcrypt.GenerateFromPassword(text, bcrypt.DefaultCost)

	// GenerateFromPassword returns a byte slice so we need to
	// convert the bytes to a string and return it
	return hash, nil
}

// CompareHashSalted will check to see if two strings are the same and returns a
// boolean.
func CompareHashSalted(hashed []byte, text []byte) bool {
	// Since we'll be getting the hashed password from the DB it
	// will be a string so we'll need to convert it to a byte slice

	// CompareHashAndPassword compares a bcrypt hashed password with its plaintext
	// equivalent, and returns nil on success, or an error on failure.
	err := bcrypt.CompareHashAndPassword(hashed, text)
	// if hashed password and text does not match, print err and return false
	if err != nil {
		log.Println(err)
		return false
	}

	return true
}

// Hash will hash a given text using the sha224 and sha256 hash algorithms.
//
// Note: type Hash interface embeds the writer interface, which is how Write
// can be invoked with type Hash.
func Hash(text []byte) string {
	h := sha256.New()
	// Write adds text to the running hash.
	h.Write(text)

	// Sum appends current hash to nil and returns a byte slice. Sum does not change
	// the underlying hash state.
	// EncodeToString returns a hexadecimal string of the current hash.
	encoded := base64.StdEncoding.EncodeToString(h.Sum(nil))
	return encoded
}

// CompareHash will check to see if the given hashed and hashed text are the same,
// and return a boolean.
func CompareHash(hashed string, text string) bool {
	// Since we'll be getting the hashed password from the DB it
	// will be a string so we'll need to convert it to a byte slice

	// hash the given text stored in byte slice and compare with given hashed.
	hash := Hash([]byte(text))
	// if the given hashed does not match the hashed text, return false
	if hashed != hash {
		return false
	}

	return true
}

// GenerateRandomHash will create a hash based on a Crypto/rand number of bytes.
//
// rand.Reader is a global, shared instance of a cryptographically
// secure pseudo-random generator. For example, on other Unix-like systems,
// Reader reads from /dev/urandom, which is a special file that serve as a
// pseudorandom number generator.
// ReadFull returns the number of bytes copied.
func GenerateRandomHash(size int) (string, error) {
	// generate a random 32 byte string

	// make initializes a key of byte slice, allocating an underlying array of size.
	key := make([]byte, size)

	// ReadFull reads the length of key from rand.Reader and copies content
	// into key. rand.Reader reads from a cryptographically secure random number generator.
	bytesCopied, err := io.ReadFull(rand.Reader, key[:])
	// if zero bytes were copied, return error
	if bytesCopied == 0 {
		return "", errors.New("no bytes were read")
	}

	return Hash(key), err
}

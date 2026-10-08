package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

type vector struct {
	Key      string `json:"key"`
	KeyHmac  string `json:"keyHmac"`
	IV       string `json:"iv"`
	Data     string `json:"data"`
	Envelope string `json:"envelope"`
}

func run() error {
	write := flag.Bool("write", false, "Regenerate deterministic Go reference vectors")
	flag.Parse()
	var vectors []vector
	for _, size := range []int{16, 24, 32} {
		for _, length := range []int{0, 1, 17, 32} {
			key := bytes.Repeat([]byte{byte(size)}, size)
			keyHmac := bytes.Repeat([]byte{0x42}, 129)
			iv := bytes.Repeat([]byte{0x13}, aes.BlockSize)
			data := bytes.Repeat([]byte{0x57}, length)
			block, err := aes.NewCipher(key)
			if err != nil {
				return err
			}
			envelope := make([]byte, 1+aes.BlockSize+length+sha512.Size)
			envelope[0] = 1
			copy(envelope[1:], iv)
			cipher.NewCTR(block, iv).XORKeyStream(envelope[17:17+length], data)
			mac := hmac.New(sha512.New, keyHmac)
			mac.Write(envelope[1 : 17+length])
			copy(envelope[17+length:], mac.Sum(nil))
			vectors = append(vectors, vector{
				Key: hex.EncodeToString(key), KeyHmac: hex.EncodeToString(keyHmac),
				IV: hex.EncodeToString(iv), Data: hex.EncodeToString(data),
				Envelope: hex.EncodeToString(envelope),
			})
		}
	}
	encoded, err := json.MarshalIndent(vectors, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	_, source, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(source), "../fixtures/aes-ctr-hmac-vectors.json")
	if *write {
		return os.WriteFile(path, encoded, 0644)
	}
	existing, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(existing, encoded) {
		return fmt.Errorf("AES-CTR/HMAC fixtures differ from Go reference")
	}
	fmt.Printf("PASS: %d Go AES-CTR/HMAC-SHA512 reference vectors\n", len(vectors))
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

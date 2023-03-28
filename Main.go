package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"fmt"
)

func pad(plaintext []byte, blockSize int) []byte {
	padding := blockSize - (len(plaintext) % blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plaintext, padtext...)
}

func unpad(padded []byte) []byte {
	padding := int(padded[len(padded)-1])
	return padded[:len(padded)-padding]
}

func encryptECB(plaintext []byte, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plaintext = pad(plaintext, des.BlockSize)
	ciphertext := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i += block.BlockSize() {
		block.Encrypt(ciphertext[i:], plaintext[i:])
	}
	return ciphertext, nil
}

func decryptECB(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	decryptedtext := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i += block.BlockSize() {
		block.Decrypt(decryptedtext[i:], ciphertext[i:])
	}
	decryptedtext = unpad(decryptedtext)
	return decryptedtext, nil
}

func encryptOFB(plaintext []byte, key []byte, iv []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ofb := cipher.NewOFB(block, iv)
	plaintext = pad(plaintext, des.BlockSize)
	ciphertext := make([]byte, len(plaintext))
	ofb.XORKeyStream(ciphertext, plaintext)
	return ciphertext, nil
}

func decryptOFB(ciphertext []byte, key []byte, iv []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ofb := cipher.NewOFB(block, iv)
	decryptedtext := make([]byte, len(ciphertext))
	ofb.XORKeyStream(decryptedtext, ciphertext)
	decryptedtext = unpad(decryptedtext)
	return decryptedtext, nil
}

func main() {
	// ECB example
	key := []byte("01234567") // 8-byte key
	plaintext := []byte("Hi, I'm robin!")
	fmt.Println("Plaintext:", string(plaintext))

	ciphertext, err := encryptECB(plaintext, key)
	if err != nil {
		panic(err)
	}
	fmt.Printf("ECB encrypted: %x\n", ciphertext)

	decryptedtext, err := decryptECB(ciphertext, key)
	if err != nil {
		panic(err)
	}
	fmt.Println("ECB decrypted:", string(decryptedtext))

	// OFB example
	iv := []byte("87654321") // 8-byte initialization vector
	plaintext = []byte("Hi, I'm Robin!")
	fmt.Println("Plaintext:", string(plaintext))

	ciphertext, err = encryptOFB(plaintext, key, iv)
	if err != nil {
		panic(err)
	}
	fmt.Printf("OFB encrypted: %x\n", ciphertext)

	decryptedtext, err = decryptOFB(ciphertext, key, iv)
	if err != nil {
		panic(err)
	}
	fmt.Println("OFB decrypted:", string(decryptedtext))
}

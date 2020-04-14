package sherAes

import (
	"encoding/hex"
	"fmt"
	"testing"
)

// test aesGCM encrypt
func TestAesGCM_Encrypt(t *testing.T) {
	aesGCMCipher := NewDefaultAesGCM()
	// message you want to encrypt
	plainText := []byte("Hello World!")
	// key size should larger than 32 bytes
	key := []byte("key:12345678912345678912345678912345789")
	// nonce
	iv := []byte("iv:123456789123")
	// mask data
	additionalData := []byte("additionalData:test")
	cipherText, err := aesGCMCipher.Encrypt(plainText, key, iv, additionalData)
	if err != nil {
		fmt.Println("Encrypt error:", err)
	}
	fmt.Println("Encrypted text:", hex.EncodeToString(cipherText))
}

// test aesGCM decrypt
func TestAesGCM_Decrypt(t *testing.T) {
	aesGCMCipher := NewDefaultAesGCM()
	cipherText, _ := hex.DecodeString("e50d7983b9cd370d81acdda56f5f6e15765ca3a537071eb18eedc27e")
	// key size should larger than 32 bytes
	key := []byte("key:12345678912345678912345678912345789")
	// nonce
	iv := []byte("iv:123456789123")
	// mask data
	additionalData := []byte("additionalData:test")
	plainText, err := aesGCMCipher.Decrypt(cipherText, key, iv, additionalData)
	if err != nil {
		fmt.Println("Encrypt error:", err)
	}
	fmt.Println("Plain text:", string(plainText))
}

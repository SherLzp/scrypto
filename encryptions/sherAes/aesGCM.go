package sherAes

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"fmt"
)

type aesGCM struct {
	gcmStandardNonceSize, gcmKeySize int
}

func NewDefaultAesGCM() (aesGCMCipher *aesGCM) {
	aesGCMCipher = &aesGCM{
		gcmStandardNonceSize: 12,
		gcmKeySize:           32,
	}
	return aesGCMCipher
}

// encrypt message
// @plainText: message you want to encrypt
// @key: key which is used to encrypt
// @iv: nonce which is used in encryption
// @additionalData: data which is used to mask plainText
func (this *aesGCM) Encrypt(plainText []byte, key []byte, iv []byte, additionalData []byte) (cipherText []byte, err error) {
	// key size should larger than 32 bytes
	if len(key) < this.gcmKeySize {
		return nil, errors.New("key size not match: key should larger than 32 bytes")
	}
	// iv size should larger than 12 bytes
	if len(iv) < this.gcmStandardNonceSize {
		return nil, errors.New("iv size not match: iv should larger than 12 bytes")
	}
	// create block cipher
	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return nil, err
	}
	// create gcm cipher
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	// encrypt plainText
	cipherText = aesGCM.Seal(nil, iv[:12], plainText, additionalData)
	return cipherText, nil
}

// decrypt encrypted message
// @cipherText: message you want to decrypt
// @key: key which is used to encrypt
// @iv: nonce which is used in encryption
// @additionalData: data which was used to mask plainText
func (this *aesGCM) Decrypt(cipherText []byte, key []byte, iv []byte, additionalData []byte) (plainText []byte, err error) {
	// key size should larger than 32 bytes
	if len(key) < this.gcmKeySize {
		return nil, errors.New("key size not match: key should larger than 32 bytes")
	}
	// iv size should larger than 12 bytes
	if len(iv) < this.gcmStandardNonceSize {
		return nil, errors.New("iv size not match: iv should larger than 12 bytes")
	}
	// create block cipher
	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return nil, err
	}
	// create gcm cipher
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	// decrypt the cipherText
	plainText, err = aesGCM.Open(nil, iv[:12], cipherText, additionalData)
	if err != nil {
		return nil, err
	}
	return plainText, nil
}

func TryOnce() {
	fmt.Println("-----------AES GCM start-------------")
	// create aes gcm cipher
	aesGCMCipher := NewDefaultAesGCM()
	// message you want to encrypt
	plainText := []byte("Hello World")
	fmt.Println("PlainText:", string(plainText))
	fmt.Println("plaintext length:", len(plainText))
	// key size should larger than 32 bytes
	key := []byte("key:12345678912345678912345678912345789")
	// nonce
	iv := []byte("iv:123456789123")
	cipherText, err := aesGCMCipher.Encrypt(plainText, key, iv, nil)
	if err != nil {
		panic(err)
	}
	fmt.Println("CipherText:", hex.EncodeToString(cipherText))
	fmt.Println("cipherText length:", len(cipherText))
	decryptText, err := aesGCMCipher.Decrypt(cipherText, key, iv, nil)
	if err != nil {
		panic(err)
	}
	fmt.Println("Text after decryption:", string(decryptText))
	fmt.Println("Text after decryption length:", len(string(decryptText)))
	fmt.Println("-----------AES GCM end-------------")
}

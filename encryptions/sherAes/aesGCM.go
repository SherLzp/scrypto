package sherAes

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
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
	// key size should be 32 bytes
	if len(key) != this.gcmKeySize {
		return nil, errors.New("key size not match: key should be 32 bytes")
	}
	// iv size should be 12 bytes
	if len(iv) != this.gcmKeySize {
		return nil, errors.New("iv size not match: iv should be 12 bytes")
	}
	// create block cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// create gcm cipher
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	// encrypt plainText
	cipherText = aesGCM.Seal(nil, iv, plainText, additionalData)
	return cipherText, nil
}

// decrypt encrypted message
// @cipherText: message you want to decrypt
// @key: key which is used to encrypt
// @iv: nonce which is used in encryption
// @additionalData: data which was used to mask plainText
func (this *aesGCM) Decrypt(cipherText []byte, key []byte, iv []byte, additionalData []byte) (plainText []byte, err error) {
	// key size should be 32 bytes
	if len(key) != this.gcmKeySize {
		return nil, errors.New("key size not match: key should be 32 bytes")
	}
	// iv size should be 12 bytes
	if len(iv) != this.gcmStandardNonceSize {
		return nil, errors.New("iv size not match: iv should be 12 bytes")
	}
	// create block cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// create gcm cipher
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	// decrypt the cipherText
	plainText, err = aesGCM.Open(nil, iv, cipherText, additionalData)
	if err != nil {
		return nil, err
	}
	return plainText, nil
}

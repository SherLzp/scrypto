package recrypt

import (
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"scrypto/dsa/ecdsa"
	"testing"
)

func TestUmbral_Encrypt(t *testing.T) {
	p256 := elliptic.P256()
	recryptCipher := NewRecryptCipher(p256)
	ecdsaSigner := ecdsaUtils.NewECDSA(p256)
	// Alice Generate Alice key-pair
	_, aPubKey, _ := ecdsaSigner.GenerateKeys()
	// Bob Generate Bob key-pair
	//_, bPubKey, _ := ecdsaSigner.GenerateKeys()
	// plain text
	m := []byte("Hello, Proxy Re-Encryption")
	fmt.Println("origin message:", string(m))
	// Alice encrypts to get cipherText and capsule
	cipherText, capsule, err := recryptCipher.Encrypt(m, aPubKey)
	if err != nil {
		panic(err)
	}
	capsuleAsBytes, err := recryptCipher.EncodeCapsule(*capsule)
	if err != nil {
		panic(err)
	}
	capsuleTest, err := recryptCipher.DecodeCapsule(capsuleAsBytes)
	if err != nil {
		panic(err)
	}
	fmt.Println("capsule before encode:", capsule)
	fmt.Println("capsule after decode:", capsuleTest)
	fmt.Println("ciphereText:", hex.EncodeToString(cipherText))
}

func TestUmbral_ReKeyGen(t *testing.T) {
	p256 := elliptic.P256()
	recryptCipher := NewRecryptCipher(p256)
	ecdsaSigner := ecdsaUtils.NewECDSA(p256)
	// Alice Generate Alice key-pair
	aPriKey, aPubKey, _ := ecdsaSigner.GenerateKeys()
	// Bob Generate Bob key-pair
	_, bPubKey, _ := ecdsaSigner.GenerateKeys()
	// plain text
	m := []byte("Hello, Proxy Re-Encryption")
	fmt.Println("origin message:", string(m))
	// Alice encrypts to get cipherText and capsule
	cipherText, capsule, err := recryptCipher.Encrypt(m, aPubKey)
	if err != nil {
		panic(err)
	}
	capsuleAsBytes, err := recryptCipher.EncodeCapsule(*capsule)
	if err != nil {
		panic(err)
	}
	capsuleTest, err := recryptCipher.DecodeCapsule(capsuleAsBytes)
	if err != nil {
		panic(err)
	}
	fmt.Println("capsule before encode:", capsule)
	fmt.Println("capsule after decode:", capsuleTest)
	fmt.Println("ciphereText:", hex.EncodeToString(cipherText))
	// Test recreate aes key
	keyBytes, err := recryptCipher.RecreateAESKeyByMyPriKey(capsule, aPriKey)
	if err != nil {
		panic(err)
	}
	fmt.Println("recreate key:", hex.EncodeToString(keyBytes))
	// Alice generates re-encryption key
	rk, _, err := recryptCipher.ReKeyGen(aPriKey, bPubKey)
	if err != nil {
		panic(err)
	}
	fmt.Println("rk:", rk)
}

func TestUmbral_ReEncryption(t *testing.T) {
	p256 := elliptic.P256()
	recryptCipher := NewRecryptCipher(p256)
	ecdsaSigner := ecdsaUtils.NewECDSA(p256)
	// Alice Generate Alice key-pair
	aPriKey, aPubKey, _ := ecdsaSigner.GenerateKeys()
	// Bob Generate Bob key-pair
	_, bPubKey, _ := ecdsaSigner.GenerateKeys()
	// plain text
	m := []byte("Hello, Proxy Re-Encryption")
	fmt.Println("origin message:", string(m))
	// Alice encrypts to get cipherText and capsule
	cipherText, capsule, err := recryptCipher.Encrypt(m, aPubKey)
	if err != nil {
		panic(err)
	}
	capsuleAsBytes, err := recryptCipher.EncodeCapsule(*capsule)
	if err != nil {
		panic(err)
	}
	capsuleTest, err := recryptCipher.DecodeCapsule(capsuleAsBytes)
	if err != nil {
		panic(err)
	}
	fmt.Println("capsule before encode:", capsule)
	fmt.Println("capsule after decode:", capsuleTest)
	fmt.Println("ciphereText:", hex.EncodeToString(cipherText))
	// Test recreate aes key
	keyBytes, err := recryptCipher.RecreateAESKeyByMyPriKey(capsule, aPriKey)
	if err != nil {
		panic(err)
	}
	fmt.Println("recreate key:", hex.EncodeToString(keyBytes))
	// Alice generates re-encryption key
	rk, _, err := recryptCipher.ReKeyGen(aPriKey, bPubKey)
	if err != nil {
		panic(err)
	}
	fmt.Println("rk:", rk)
	// Server executes re-encrypt
	newCapsule, err := recryptCipher.ReEncryption(rk, capsule)
	if err != nil {
		panic(err)
	}
	capsuleBytes, err := recryptCipher.EncodeCapsule(*newCapsule)
	if err != nil {
		panic(err)
	}
	fmt.Println("newCapsule:", capsuleBytes)
}

func TestUmbral_Decrypt(t *testing.T) {
	p256 := elliptic.P256()
	recryptCipher := NewRecryptCipher(p256)
	ecdsaSigner := ecdsaUtils.NewECDSA(p256)
	// Alice Generate Alice key-pair
	aPriKey, aPubKey, _ := ecdsaSigner.GenerateKeys()
	// Bob Generate Bob key-pair
	bPriKey, bPubKey, _ := ecdsaSigner.GenerateKeys()
	// plain text
	m := []byte("Hello, Proxy Re-Encryption")
	fmt.Println("origin message:", string(m))
	// Alice encrypts to get cipherText and capsule
	cipherText, capsule, err := recryptCipher.Encrypt(m, aPubKey)
	if err != nil {
		panic(err)
	}
	capsuleAsBytes, err := recryptCipher.EncodeCapsule(*capsule)
	if err != nil {
		panic(err)
	}
	capsuleTest, err := recryptCipher.DecodeCapsule(capsuleAsBytes)
	if err != nil {
		panic(err)
	}
	fmt.Println("capsule before encode:", capsule)
	fmt.Println("capsule after decode:", capsuleTest)
	fmt.Println("ciphereText:", hex.EncodeToString(cipherText))
	// Test recreate aes key
	keyBytes, err := recryptCipher.RecreateAESKeyByMyPriKey(capsule, aPriKey)
	if err != nil {
		panic(err)
	}
	fmt.Println("recreate key:", hex.EncodeToString(keyBytes))
	// Alice generates re-encryption key
	rk, pubX, err := recryptCipher.ReKeyGen(aPriKey, bPubKey)
	if err != nil {
		panic(err)
	}
	fmt.Println("rk:", rk)
	// Server executes re-encrypt
	newCapsule, err := recryptCipher.ReEncryption(rk, capsule)
	if err != nil {
		panic(err)
	}
	// Bob decrypts the cipherText
	plainText, err := recryptCipher.Decrypt(bPriKey, newCapsule, pubX, cipherText)
	if err != nil {
		panic(err)
	}
	// get plainText
	fmt.Println("plainText:", string(plainText))
}

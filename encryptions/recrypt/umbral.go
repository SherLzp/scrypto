package recrypt

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"math/big"
	"shercrypto/ecc/p256Utils"
	"shercrypto/encryptions/sherAes"
	sherMath "shercrypto/math"
	"shercrypto/signatures/ecdsa"
	sherUtils "shercrypto/utils"
)

type CurvePoint = ecdsa.PublicKey

type Umbral struct {
	curve elliptic.Curve
	N     *big.Int
}

type Capsule struct {
	E *CurvePoint
	V *CurvePoint
	S *big.Int
}

func NewRecryptCipher(curve elliptic.Curve) (recryptCipher *Umbral) {
	recryptCipher = &Umbral{
		curve: curve,
		N:     curve.Params().N,
	}
	return recryptCipher
}

func (this *Umbral) encryptKeyGen(pubKey *ecdsa.PublicKey) (capsule *Capsule, keyBytes []byte, err error) {
	// generate E,V key-pairs
	ecdsaSigner := ecdsaUtils.NewECDSA(this.curve)
	e, E, err := ecdsaSigner.GenerateKeys()
	v, V, err := ecdsaSigner.GenerateKeys()
	if err != nil {
		return nil, nil, err
	}
	// get H2(E || V)
	EV := sherUtils.ContactBytes(p256Utils.Marshal(E), p256Utils.Marshal(V))
	h := p256Utils.HashToCurve(EV)
	if err != nil {
		return nil, nil, err
	}
	// get s = v + e * H2(E || V)
	s := sherMath.Add(v.D, sherMath.Mul(e.D, h, this.N), this.N)
	// get (pk_A)^{e+v}
	point := p256Utils.ScalarMult(pubKey, sherMath.Add(e.D, v.D, this.N))
	// generate aes key
	keyBytes, err = sherUtils.Sha3Hash(p256Utils.Marshal(point))
	if err != nil {
		return nil, nil, err
	}
	capsule = &Capsule{
		E: E,
		V: V,
		S: s,
	}
	return capsule, keyBytes, nil
}

// Recreate aes key
func (this *Umbral) RecreateAESKeyByMyPriKey(capsule *Capsule, aPriKey *ecdsa.PrivateKey) (keyBytes []byte, err error) {
	point := p256Utils.ScalarAdd(capsule.E, capsule.V)
	point = p256Utils.ScalarMult(point, aPriKey.D)
	// generate aes key
	keyBytes, err = sherUtils.Sha3Hash(p256Utils.Marshal(point))
	if err != nil {
		return nil, err
	}
	return keyBytes, nil
}

func (this *Umbral) RecreateAESKeyByMyPriKeyStr(capsule *Capsule, aPriKeyStr string) (keyBytes []byte, err error) {
	aPriKey, err := p256Utils.PrivateKeyStrToKey(aPriKeyStr)
	if err != nil {
		return nil, err
	}
	return this.RecreateAESKeyByMyPriKey(capsule, aPriKey)
}

func (this *Umbral) EncryptMessageByAESKey(message []byte, keyBytes []byte, pubKey *ecdsa.PublicKey) (cipherText []byte, err error) {
	// use aes gcm algorithm to encrypt
	// mark keyBytes[:12] as nonce
	pubKeyBytes := p256Utils.Marshal(pubKey)
	aesGCMCipher := sherAes.NewDefaultAesGCM()
	cipherText, err = aesGCMCipher.Encrypt(message, keyBytes, pubKeyBytes, nil)
	if err != nil {
		return nil, err
	}
	return cipherText, nil
}

// Encrypt the message
// AES GCM + Proxy Re-Encryption
func (this *Umbral) Encrypt(message []byte, pubKey *ecdsa.PublicKey) (cipherText []byte, capsule *Capsule, err error) {
	capsule, keyBytes, err := this.encryptKeyGen(pubKey)
	if err != nil {
		return nil, nil, err
	}
	fmt.Println("Origin key:", hex.EncodeToString(keyBytes))
	// use aes gcm algorithm to encrypt
	// mark keyBytes[:12] as nonce
	aesGCMCipher := sherAes.NewDefaultAesGCM()
	cipherText, err = aesGCMCipher.Encrypt(message, keyBytes, keyBytes, nil)
	if err != nil {
		return nil, nil, err
	}
	return cipherText, capsule, nil
}

func (this *Umbral) EncryptByStr(message, pubKeyStr string) (cipherText []byte, capsule *Capsule, err error) {
	key, err := p256Utils.PublicKeyStrToKey(pubKeyStr)
	if err != nil {
		return nil, nil, err
	}
	return this.Encrypt([]byte(message), key)
}

// generate re-encryption key and sends it to Server
// rk = sk_A * d^{-1}
func (this *Umbral) ReKeyGen(aPriKey *ecdsa.PrivateKey, bPubKey *ecdsa.PublicKey) (rk *big.Int, pubX *ecdsa.PublicKey, err error) {
	// generate x,X key-pair
	p256 := elliptic.P256()
	ecdsaSigner := ecdsaUtils.NewECDSA(p256)
	priX, pubX, err := ecdsaSigner.GenerateKeys()
	if err != nil {
		return nil, nil, err
	}
	// get d = H3(X_A || pk_B || pk_B^{x_A})
	Bx := p256Utils.ScalarMult(bPubKey, priX.D)
	dPre := sherUtils.ContactBytes(p256Utils.Marshal(pubX), p256Utils.Marshal(bPubKey), p256Utils.Marshal(Bx))
	d := p256Utils.HashToCurve(dPre)
	// rk = sk_A * d^{-1}
	rk = sherMath.Mul(aPriKey.D, sherMath.ModInverse(d, this.N), this.N)
	return rk, pubX, nil
}

func (this *Umbral) ReKeyGenByStr(aPriKeyStr, bPubKeyStr string) (rk *big.Int, pubX *ecdsa.PublicKey, err error) {
	aPriKey, err := p256Utils.PrivateKeyStrToKey(aPriKeyStr)
	if err != nil {
		return nil, nil, err
	}
	bPubKey, err := p256Utils.PublicKeyStrToKey(bPubKeyStr)
	if err != nil {
		return nil, nil, err
	}
	return this.ReKeyGen(aPriKey, bPubKey)
}

// Server executes Re-Encryption method
func (this *Umbral) ReEncryption(rk *big.Int, capsule *Capsule) (newCapsule *Capsule, err error) {
	// check g^s == V * E^{H2(E || V)}
	S := p256Utils.ScalarBaseMult(capsule.S)
	h2 := p256Utils.HashToCurve(
		sherUtils.ContactBytes(
			p256Utils.Marshal(capsule.E),
			p256Utils.Marshal(capsule.V)))
	Eh2 := p256Utils.ScalarMult(capsule.E, h2)
	VEh2 := p256Utils.ScalarAdd(capsule.V, Eh2)
	// if check failed return error
	if !p256Utils.IsEqual(S, VEh2) {
		return nil, fmt.Errorf("%s", "Capsule not match")
	}
	// E' = E^{rk}, V' = V^{rk}
	newCapsule = &Capsule{
		E: p256Utils.ScalarMult(capsule.E, rk),
		V: p256Utils.ScalarMult(capsule.V, rk),
		S: capsule.S,
	}
	return newCapsule, nil
}

func (this *Umbral) decryptKeyGen(bPriKey *ecdsa.PrivateKey, capsule *Capsule, pubX *ecdsa.PublicKey) (keyBytes []byte, err error) {
	// S = X_A^{sk_B}
	S := p256Utils.ScalarMult(pubX, bPriKey.D)
	SBytes := p256Utils.Marshal(S)
	pubBBytes := p256Utils.Marshal(&bPriKey.PublicKey)
	pubXBytes := p256Utils.Marshal(pubX)
	// recreate d = H3(X_A || pk_B || S)
	d := p256Utils.HashToCurve(sherUtils.ContactBytes(pubXBytes, pubBBytes, SBytes))
	point := p256Utils.ScalarMult(p256Utils.ScalarAdd(capsule.E, capsule.V), d)
	keyBytes, err = sherUtils.Sha3Hash(p256Utils.Marshal(point))
	if err != nil {
		return nil, err
	}
	return keyBytes, nil
}

// Recreate the aes key then decrypt the cipherText
func (this *Umbral) Decrypt(bPriKey *ecdsa.PrivateKey, capsule *Capsule, pubX *ecdsa.PublicKey, cipherText []byte) (plainText []byte, err error) {
	keyBytes, err := this.decryptKeyGen(bPriKey, capsule, pubX)
	if err != nil {
		return nil, err
	}
	// recreate aes key = G((E' * V')^d)
	// use aes gcm to decrypt
	// mark keyBytes[:12] as nonce
	aesGCMCipher := sherAes.NewDefaultAesGCM()
	plainText, err = aesGCMCipher.Decrypt(cipherText, keyBytes, keyBytes, nil)
	if err != nil {
		return nil, err
	}
	return plainText, nil
}

func (this *Umbral) DecryptByStr(bPriKeyStr string, capsule *Capsule, pubXStr string, cipherText []byte) (plainText []byte, err error) {
	bPriKey, err := p256Utils.PrivateKeyStrToKey(bPriKeyStr)
	if err != nil {
		return nil, err
	}
	pubX, err := p256Utils.PublicKeyStrToKey(pubXStr)
	if err != nil {
		return nil, err
	}
	return this.Decrypt(bPriKey, capsule, pubX, cipherText)
}

// Decrypt by my own private key
func (this *Umbral) DecryptOnMyPriKey(aPriKey *ecdsa.PrivateKey, capsule *Capsule, cipherText []byte) (plainText []byte, err error) {
	keyBytes, err := this.RecreateAESKeyByMyPriKey(capsule, aPriKey)
	if err != nil {
		return nil, err
	}
	// use aes gcm algorithm to encrypt
	// mark keyBytes[:12] as nonce
	aesGCMCipher := sherAes.NewDefaultAesGCM()
	plainText, err = aesGCMCipher.Decrypt(cipherText, keyBytes, keyBytes, nil)
	return plainText, err
}

func (this *Umbral) DecryptOnMyOwnStrKey(aPriKeyStr string, capsule *Capsule, cipherText []byte) (plainText []byte, err error) {
	aPriKey, err := p256Utils.PrivateKeyStrToKey(aPriKeyStr)
	if err != nil {
		return nil, err
	}
	return this.DecryptOnMyPriKey(aPriKey, capsule, cipherText)
}

func (this *Umbral) EncodeCapsule(capsule Capsule) (capsuleAsBytes []byte, err error) {
	gob.Register(elliptic.P256())
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	if err = enc.Encode(capsule); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (this *Umbral) DecodeCapsule(capsuleAsBytes []byte) (capsule Capsule, err error) {
	capsule = Capsule{}
	gob.Register(this.curve)
	dec := gob.NewDecoder(bytes.NewBuffer(capsuleAsBytes))
	if err = dec.Decode(&capsule); err != nil {
		return capsule, err
	}
	return capsule, nil
}

func TryOnce() {
	fmt.Println("-----------Umbral Recrypt start-------------")
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

	plainTextByMyPri, err := recryptCipher.DecryptOnMyPriKey(aPriKey, capsule, cipherText)
	if err != nil {
		panic(err)
	}
	fmt.Println("PlainText by my own private key:", string(plainTextByMyPri))
	// get plainText
	fmt.Println("plainText:", string(plainText))
	fmt.Println("-----------Umbral Recrypt end-------------")
}

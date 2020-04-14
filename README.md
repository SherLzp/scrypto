# shercrypto

The project is a crypto library written by [myself](https://www.sher.vip). This is a long-term task, and the project is still in its infancy. There is still much to be done.

# Directory Structure

```sh
├─ecc # elliptic curve utils
│  └─p256Utils # P256 curve utils
├─encryptions # Encryption algorithms
│  └─sherAes # AES algorithm
│      └─assets
├─math # wrapped math algorithms
├─signatures # Signature algorithms
│  ├─algebraicMAC
│  │  └─assets
│  └─ringers17
│      └─assets
├─utils # utils used in our project
└─zeroKnowledge # zero-knowledge algorithms
    └─schnorrNIZK
        └─assets
```

# Curves

- [x] P256(secp256k1)
- [x] BN256
- [ ] Curve25519(ed25519)
- [ ] BLS381
- [ ] BLS377

# Algorithms

## Encryptions

### AES

- [x] [AES_GCM](encryptions/sherAes)
- [ ] AES_CBC
- [ ] AES_OFB
- [ ] ...

### Proxy Re-Encryption

- [x] [Proxy Re-Encryption](https://github.com/SherLzp/goRecrypt) (which will be moved to here later)
- [ ] PRE based on pairing curves

### Signatures
- [x] [Algebraic MAC](signatures\algebraicMAC)
- [x] [An efficient self-blindable attribute-based credential scheme](signatures\ringers17) (Only demo part)

### Zero-Knowledge
- [x] [Schnorr NIZK](zeroKnowledge\schnorrNIZK)
- [ ] Groth16
- [ ] SuperSonic
- [ ] Plonk
- [ ] ...

# API

waiting...

# Try Once

## main.go

```go
package main

import (
	"shercrypto/encryptions/sherAes"
	"shercrypto/signatures/algebraicMAC"
	"shercrypto/signatures/ringers17"
	"shercrypto/zeroKnowledge/schnorrNIZK"
)

func main() {
	sherAes.TryOnce()
	ringers17.TryOnce()
	schnorrNIZK.TryOnce()
	algebraicMAC.TryOnce()
}
```

## result

### AES GCM

```go
-----------AES GCM start-------------
PlainText: Hello World
CipherText: e50d7983b9cd370d81acdd6b8ead71ebce7c673360dbe414dda6d2
Text after decryption: Hello World
-----------AES GCM end-------------
```

### ringers17

```go
-----------Self-blindable Attribute-based Credential start-------------
-----------Pair test start-------------
ePaQ == ePQa == ePQ: true
-----------Pair test end-------------
-----------Verify signature test start-------------
eSQ==eKA: true
eS1Q==eKA1: true
eS2Q==eKA2: true
eTQ==eCZ: true
-----------Verify signature test end-------------
-----------Verify modified signature start-------------
eS_baQ == eK_baA: true
eS1_baQ == eK_baA1: true
eS2_baQ == eK_baA2: true
eS2_baQ == eK_baA2: true
-----------Verify modified signature end-------------
-----------Self-blindable Attribute-based Credential end-------------
```

### Schnorr NIZK

```go
-----------Schnorr NIZK start-------------
t == gryc: true
-----------Schnorr NIZK end-------------
```

### Algebraic MAC

```go
-----------MacWBB start-------------
sk size: 4
sk: [106017937484796436621171128186556067169437328187986909192787030517387715481638 105082266742337798259974220088418614575575463280961935755667381568265392101400 95299959137387478728840459462843114179874893670660714576107584043417810861749 106229159311665134080116624624806628752700675425199308730401530126750157338520]
pk size: 4
pk: [0xc0003f9f20 0xc0003f9fa0 0xc0003f4020 0xc0003f4100]
mVec(i+5)  0 : 5
mVec(i+5)  1 : 6
mVec(i+5)  2 : 7
mVec size: 3
sigma : [4 42 81 144 251 183 77 67 221 44 154 221 170 214 127 252 7 198 206 7 67 123 241 60 21 229 15 192 61 170 73 32 242 157 210 172 64 154 100 151 237 194 222 129 199 25 165 81 3 238 239 227 44 117 8 193 180 26 140 99 178 77 243 14 115]
sigma: [4 130 140 248 152 238 198 252 79 133 120 185 63 91 250 42 212 241 192 23 123 86 51 57 91 181 132 127 142 162 70 170 15 73 51 123 156 66 88 122 12 174 250 242 128 63 101 245 160 147 79 43 180 122 120 210 115 176 119 168 138 62 67 32 255]
sigma: [4 195 241 140 39 150 3 110 12 240 110 142 51 233 236 13 171 10 213 15 21 135 44 94 152 80 202 114 110 26 9 112 146 146 74 22 8 147 84 173 172 47 30 35 223 74 35 100 86 97 160 99 185 69 144 50 186 24 168 218 45 191 208 206 194]
sigma: [4 188 225 37 42 38 226 171 101 6 247 2 202 64 40 114 38 139 208 255 71 123 177 132 24 50 114 227 53 135 72 117 150 212 119 134 220 14 58 128 164 59 149 23 124 233 165 12 254 152 113 66 38 88 208 248 244 158 92 31 25 20 129 34 195]
sigmas size: 4
Verify result: true
-----------MacWBB end-------------
```

Thanks!
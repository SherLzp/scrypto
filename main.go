package main

import (
	"shercrypto/encryptions/recrypt"
	"shercrypto/encryptions/sherAes"
	"shercrypto/proof/credentials"
	"shercrypto/proof/schnorrNIZK"
	"shercrypto/signatures/algebraicMAC"
	"shercrypto/signatures/ringers17"
)

func main() {
	sherAes.TryOnce()
	schnorrNIZK.TryOnce()
	algebraicMAC.TryOnce()
	recrypt.TryOnce()
	ringers17.TryOnce()
	credentials.TryOnce()
}

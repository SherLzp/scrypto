package main

import (
	"shercrypto/encryptions/recrypt"
	"shercrypto/encryptions/sherAes"
	"shercrypto/proof/schnorrNIZK"
	"shercrypto/signatures/algebraicMAC"
	"shercrypto/signatures/ringers17"
)

func main() {
	sherAes.TryOnce()
	ringers17.TryOnce()
	schnorrNIZK.TryOnce()
	algebraicMAC.TryOnce()
	recrypt.TryOnce()
}

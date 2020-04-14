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

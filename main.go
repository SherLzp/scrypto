package main

import (
	"shercrypto/signatures/ringers17"
	"shercrypto/zeroKnowledge/schnorrNIZK"
)

func main() {
	ringers17.TryOnce()
	schnorrNIZK.TryOnce()
}

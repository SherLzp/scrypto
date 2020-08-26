package merkleTree

import (
	"crypto/sha256"
	"fmt"
	"shercrypto/xutils"
	"testing"
)

var (
	name     = []byte("name")
	age      = []byte("age")
	identity = []byte("identity")
	values   = [][]byte{name, age, identity}
)
// Tree
//             h(h(1,2),h(3,4))
//       h(1,2)              h(3,4)
//h(name)	h(age)	h(identity)	h(identity)
//1	        2	    3	        4

func TestNewTree(t *testing.T) {
	ageBytes, _ := xutils.GetHashValue(age, sha256.New)
	fmt.Println("ageBytes:", ageBytes)
	tree, err := NewTree(values)
	if err != nil {
		panic(err)
	}
	fmt.Println("Leaves:", tree.Leaves)

}

func TestMerkleTree_GetMerklePath(t *testing.T) {
	tree, err := NewTree(values)
	if err != nil {
		panic(err)
	}
	merklePath, index, err := tree.GetMerklePath(name)
	if err != nil {
		panic(err)
	}
	fmt.Println("Merkle Path:", merklePath)
	fmt.Println("index:", index)
}

func TestMerkleTree_VerifyValue(t *testing.T) {
	tree, err := NewTree(values)
	if err != nil {
		panic(err)
	}
	isValid, err := tree.VerifyValue(age)
	if err != nil {
		panic(err)
	}
	fmt.Println("is valid value:", isValid)
}

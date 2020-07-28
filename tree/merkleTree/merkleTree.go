package merkleTree

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"shercrypto/sherUtils"
)

type MerkleTree struct {
	Root         *Node            // Root node of Merkle Tree
	Leaves       []*Node          // Leaves
	hashStrategy func() hash.Hash // hash function
	rootHash     []byte           // root node hash value
}

type Node struct {
	Parent  *Node  // parent node
	Left    *Node  // left node
	Right   *Node  // right node
	leaf    bool   // is leaf or not
	dup     bool   // is duplicate node or not
	HashVal []byte // hash value of the node
}

//NewTree creates a new Merkle Tree using the bytes vector.
func NewTree(values [][]byte) (t *MerkleTree, err error) {
	var defaultHashStrategy = sha256.New
	t = &MerkleTree{
		hashStrategy: defaultHashStrategy,
	}
	root, leaves, err := buildWithValues(values, t)
	if err != nil {
		return nil, err
	}
	t.Root = root
	t.Leaves = leaves
	t.rootHash = root.HashVal
	return t, nil
}

func buildWithValues(values [][]byte, t *MerkleTree) (root *Node, leaves []*Node, err error) {
	if len(values) == 0 {
		return nil, nil, errors.New("error: cannot construct tree with no values")
	}
	for _, val := range values {
		h := t.hashStrategy
		hashVal, err := sherUtils.GetHashValue(val, h)
		if err != nil {
			return nil, nil, err
		}
		leaves = append(leaves, &Node{
			HashVal: hashVal,
			leaf:    true,
		})
	}

	if len(leaves)%2 == 1 {
		duplicate := &Node{
			HashVal: leaves[len(leaves)-1].HashVal,
			leaf:    true,
			dup:     true,
		}
		leaves = append(leaves, duplicate)
	}

	root, err = buildIntermediate(leaves, t)
	if err != nil {
		return nil, nil, err
	}

	return root, leaves, nil
}

func buildIntermediate(nodes []*Node, t *MerkleTree) (root *Node, err error) {
	var newNodes []*Node
	for i := 0; i < len(nodes); i += 2 {
		left, right := i, i+1
		if i+1 == len(nodes) {
			right = i
		}
		chash := append(nodes[left].HashVal, nodes[right].HashVal...)
		h := t.hashStrategy
		hashVal, err := sherUtils.GetHashValue(chash, h)
		if err != nil {
			return nil, err
		}
		node := &Node{
			Left:    nodes[left],
			Right:   nodes[right],
			HashVal: hashVal,
		}
		newNodes = append(newNodes, node)
		nodes[left].Parent = node
		nodes[right].Parent = node
		if len(nodes) == 2 {
			return node, nil
		}
	}
	return buildIntermediate(newNodes, t)
}

//MerkleRoot returns the unverified Merkle Root (hash of the root node) of the tree.
func (mt *MerkleTree) MerkleRoot() []byte {
	return mt.rootHash
}

func NewTreeWithHashStrategy(values [][]byte, hashStrategy func() hash.Hash) (*MerkleTree, error) {
	t := &MerkleTree{
		hashStrategy: hashStrategy,
	}
	root, leaves, err := buildWithValues(values, t)
	if err != nil {
		return nil, err
	}
	t.Root = root
	t.Leaves = leaves
	t.rootHash = root.HashVal
	return t, nil
}

// GetMerklePath: Get Merkle path and indexes(left leaf or right leaf)
func (mt *MerkleTree) GetMerklePath(value []byte) (merklePath [][]byte, index []int64, err error) {
	for _, node := range mt.Leaves {
		h := mt.hashStrategy
		hashVal, err := sherUtils.GetHashValue(value, h)
		if err != nil {
			return nil, nil, err
		}

		if bytes.Equal(node.HashVal, hashVal) {
			nodeParent := node.Parent
			for nodeParent != nil {
				if bytes.Equal(nodeParent.Left.HashVal, node.HashVal) {
					merklePath = append(merklePath, nodeParent.Right.HashVal)
					index = append(index, 1) // right leaf
				} else {
					merklePath = append(merklePath, nodeParent.Left.HashVal)
					index = append(index, 0) // left leaf
				}
				node = nodeParent
				nodeParent = nodeParent.Parent
			}
			return merklePath, index, nil
		}
	}
	return nil, nil, nil
}

func (mt *MerkleTree) VerifyValue(value []byte) (bool, error) {
	for _, node := range mt.Leaves {
		h := mt.hashStrategy
		hashVal, err := sherUtils.GetHashValue(value, h)
		if err != nil {
			return false, err
		}

		if bytes.Equal(node.HashVal, hashVal) {
			nodeParent := node.Parent
			for nodeParent != nil {
				leftBytes := nodeParent.Left.HashVal
				rightBytes := nodeParent.Right.HashVal
				cBytes := append(leftBytes, rightBytes...)
				cHashVal, err := sherUtils.GetHashValue(cBytes, h)
				if err != nil {
					return false, err
				}
				if !bytes.Equal(cHashVal, nodeParent.HashVal) {
					return false, nil
				}
				nodeParent = nodeParent.Parent
			}
			return true, nil
		}
	}
	return false, nil
}

//String returns a string representation of the node.
func (n *Node) String() string {
	return fmt.Sprintf("%t %t %v", n.leaf, n.dup, n.HashVal)
}

//String returns a string representation of the tree. Only leaf nodes are included
//in the output.
func (mt *MerkleTree) String() string {
	s := ""
	for _, l := range mt.Leaves {
		s += fmt.Sprint(l)
		s += "\n"
	}
	return s
}
